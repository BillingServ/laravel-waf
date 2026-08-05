<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Contracts\GeoIpResolver;
use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Http\Middleware\LoginProtection;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Security\Rules\CrLfRule;
use BillingServ\LaravelWaf\Security\Rules\SensitivePathRule;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\SecurityNotifier;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

final class WafRulesTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.rules.enabled', true);
        $app['config']->set('laravel-waf.rules.max_findings', 3);
        $app['config']->set('laravel-waf.rules.categories.geo.enabled', false);
        $app['config']->set('laravel-waf.notifications.enabled', false);
        $app['config']->set('laravel-waf.login.enabled', true);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(WafProtection::class)
            ->match(['GET', 'POST'], '/inspect', static fn () => response('ok'))
            ->name('inspect');

        foreach (['.env', '.git/config', 'nested/.htaccess'] as $index => $path) {
            Route::middleware(WafProtection::class)
                ->get('/'.$path, static fn () => response('sensitive'))
                ->name('sensitive-dotfile-'.$index);
        }

        Route::middleware(WafProtection::class)
            ->get('/.well-known/acme-challenge/test-token', static fn () => response('challenge-token'))
            ->name('well-known');

        Route::middleware(WafProtection::class)
            ->get('/assets/app.css', static fn () => response('stylesheet'))
            ->name('dotted-filename');

        Route::middleware(LoginProtection::class)
            ->post('/login', static function (Request $request) {
                event(new Failed('web', null, ['email' => $request->input('email')]));

                return response('invalid', 401);
            })
            ->name('login');
    }

    public function test_xss_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.40'])
            ->get('/inspect?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');
    }

    public function test_sql_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.41'])
            ->get('/inspect?q=1%20UNION%20SELECT%20password%20FROM%20users')
            ->assertStatus(403);
    }

    public function test_livewire_sql_injection_redirects_to_the_top_level_blocked_page(): void
    {
        $snapshot = json_encode([
            'data' => ['email' => '=1 UNION SELECT password FROM users'],
            'memo' => ['id' => 'test-component', 'name' => 'login', 'children' => []],
            'checksum' => 'test-checksum',
        ], JSON_THROW_ON_ERROR);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.55'])
            ->withHeaders(['X-Livewire' => 'true'])
            ->postJson('/inspect', [
                'components' => [[
                    'snapshot' => $snapshot,
                    'updates' => [],
                    'calls' => [],
                ]],
            ]);

        $response->assertOk()
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertJsonPath('components.0.effects.redirect', url('/_waf/blocked'));

        $this->get('/_waf/blocked')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertSee('Why have I been blocked?');

        $serverMemo = [
            'data' => ['email' => '=1 UNION SELECT password FROM users'],
            'checksum' => 'test-checksum',
        ];

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.56'])
            ->withHeaders(['X-Livewire' => 'true'])
            ->postJson('/inspect', [
                'fingerprint' => ['id' => 'test-component', 'name' => 'login', 'locale' => 'en'],
                'serverMemo' => $serverMemo,
                'updates' => [],
            ])
            ->assertOk()
            ->assertJsonPath('effects.redirect', url('/_waf/blocked'))
            ->assertJsonPath('serverMemo.data.email', '=1 UNION SELECT password FROM users');
    }

    public function test_rfi_is_blocked_for_a_file_like_parameter(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])
            ->get('/inspect?file=https%3A%2F%2Fevil.test%2Fpayload.txt')
            ->assertStatus(403);
    }

    public function test_lfi_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.43'])
            ->get('/inspect?file=..%2F..%2Fetc%2Fpasswd')
            ->assertStatus(403);
    }

    public function test_sensitive_dotfile_paths_are_blocked(): void
    {
        foreach (['/.env', '/.git/config', '/nested/.htaccess'] as $path) {
            $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.59'])
                ->get($path)
                ->assertStatus(403)
                ->assertHeader('X-Laravel-Waf-Blocked', 'true');
        }
    }

    public function test_well_known_and_ordinary_dotted_paths_remain_available(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.60'])
            ->get('/.well-known/acme-challenge/test-token')
            ->assertOk()
            ->assertContent('challenge-token');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.60'])
            ->get('/assets/app.css')
            ->assertOk()
            ->assertContent('stylesheet');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.60'])
            ->get('/inspect?filename=.env')
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_encoded_sensitive_dotfile_paths_are_detected(): void
    {
        foreach (['/%2eenv', '/%252eenv', '/.well-known/%252eenv'] as $path) {
            $finding = (new SensitivePathRule())->inspect(Request::create($path));

            self::assertNotNull($finding);
            self::assertSame('sensitive_dotfile', $finding->rule);
        }
    }

    public function test_command_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.49'])
            ->get('/inspect?command=%24%28id%29')
            ->assertStatus(403);
    }

    public function test_template_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.50'])
            ->get('/inspect?value=%7B%7B7%2A7%7D%7D')
            ->assertStatus(403);
    }

    public function test_nosql_operator_in_a_field_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.51'])
            ->get('/inspect?filter%5B%24ne%5D=1')
            ->assertStatus(403);
    }

    public function test_ldap_filter_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.52'])
            ->get('/inspect?filter=%28%7C%28uid%3D%2A%29%28uid%3D%2A%29%29')
            ->assertStatus(403);
    }

    public function test_crlf_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.53'])
            ->postJson('/inspect', ['next' => "safe\r\nX-Test: bad"])
            ->assertStatus(403);
    }

    public function test_crlf_rule_matches_a_decoded_value(): void
    {
        $request = Request::create('/inspect?next=%0d%0aX-Test%3A%20bad');
        $finding = (new CrLfRule(new RequestInputCollector()))->inspect($request);

        self::assertNotNull($finding);
    }

    public function test_ssrf_to_a_loopback_address_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.54'])
            ->get('/inspect?url=http%3A%2F%2F127.0.0.1%2Fadmin')
            ->assertStatus(403);
    }

    public function test_findings_can_be_logged_without_blocking(): void
    {
        config()->set('laravel-waf.rules.mode', 'log');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.44'])
            ->get('/inspect?name=%3Cscript%3E')
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_geo_policy_uses_a_custom_resolver(): void
    {
        config()->set('laravel-waf.rules.categories.geo.enabled', true);
        config()->set('laravel-waf.geo.allowed_countries', ['GB']);
        $this->app->instance(GeoIpResolver::class, new class implements GeoIpResolver {
            public function country(string $ip): ?string
            {
                return 'US';
            }
        });

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.45'])
            ->get('/inspect')
            ->assertStatus(403);
    }

    public function test_challenge_action_can_be_used_for_a_finding(): void
    {
        config()->set('laravel-waf.rules.categories.xss.action', 'challenge');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.46'])
            ->get('/inspect?name=%3Cscript%3E')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
    }

    public function test_completed_rule_challenge_allows_the_original_request(): void
    {
        config()->set('laravel-waf.rules.categories.xss.action', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        $this->app->instance(ChallengeVerifier::class, new class implements ChallengeVerifier {
            public function verify(mixed $payload): bool
            {
                return $payload === 'valid-payload';
            }
        });

        $server = ['REMOTE_ADDR' => '203.0.113.57'];
        $challenge = $this->withServerVariables($server)
            ->get('/inspect?name=%3Cscript%3E');

        $challenge->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
        preg_match('/name="_waf_challenge" value="([^"]+)"/', $challenge->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);

        $verification = $this->withServerVariables($server)->post('/_waf/challenge/verify', [
            '_waf_challenge' => $matches[1],
            'altcha' => 'valid-payload',
        ]);

        $verification->assertRedirect('/inspect?name=%3Cscript%3E')->assertStatus(303);
        $cookies = $verification->baseResponse->headers->getCookies();
        self::assertCount(1, $cookies);

        $this->withUnencryptedCookie($cookies[0]->getName(), $cookies[0]->getValue())
            ->withServerVariables($server)
            ->get('/inspect?name=%3Cscript%3E')
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_completed_challenge_does_not_bypass_reject_rules(): void
    {
        $ip = '203.0.113.58';
        $pass = app(ChallengeTokenManager::class)->issuePass($ip, 600);
        self::assertNotNull($pass);

        $this->withUnencryptedCookie('laravel_waf_challenge', $pass)
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->get('/inspect?name=%3Cscript%3E')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');
    }

    public function test_notifications_receive_redacted_findings(): void
    {
        config()->set('laravel-waf.notifications.enabled', true);
        $sink = new RecordingNotificationSink();
        $this->app->instance(NotificationSink::class, $sink);
        $this->app->forgetInstance(SecurityNotifier::class);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.47'])
            ->get('/inspect?name=%3Cscript%3Esecret-value%3C%2Fscript%3E')
            ->assertStatus(403);

        self::assertCount(1, $sink->findings);
        self::assertSame('xss', $sink->findings[0]->category);
        self::assertStringNotContainsString('secret-value', json_encode($sink->findings[0]->context(), JSON_THROW_ON_ERROR));
    }

    public function test_login_failures_are_rate_limited(): void
    {
        config()->set('laravel-waf.login.max_attempts', 2);
        config()->set('laravel-waf.login.decay_seconds', 60);

        $server = ['REMOTE_ADDR' => '203.0.113.48'];
        $this->withServerVariables($server)->post('/login', ['email' => 'user@example.test'])->assertStatus(401);
        $this->withServerVariables($server)->post('/login', ['email' => 'user@example.test'])->assertStatus(401);
        $this->withServerVariables($server)->post('/login', ['email' => 'user@example.test'])->assertStatus(429);
    }
}

final class RecordingNotificationSink implements NotificationSink
{
    /** @var array<int, Finding> */
    public array $findings = [];

    public function notify(Finding $finding): void
    {
        $this->findings[] = $finding;
    }
}

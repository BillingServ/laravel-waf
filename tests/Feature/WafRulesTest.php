<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
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

    public function test_xss_password_returns_the_blocked_page_in_the_same_response(): void
    {
        config()->set('laravel-waf.agent.enabled', true);
        config()->set('laravel-waf.agent.auto_block_on_finding', true);
        $decisionSink = new RecordingDecisionSink();
        app()->instance(DecisionSink::class, $decisionSink);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.141'])
            ->post('/inspect', ['password' => '<script>alert(1)</script>'])
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertSee('Why have I been blocked?');

        self::assertSame(1, $decisionSink->blocks);
    }

    public function test_loopback_findings_never_create_firewall_blocks(): void
    {
        config()->set('laravel-waf.agent.enabled', true);
        config()->set('laravel-waf.agent.auto_block_on_finding', true);
        $decisionSink = new RecordingDecisionSink();
        app()->instance(DecisionSink::class, $decisionSink);

        foreach (['127.0.0.1', '127.0.0.42', '::1'] as $ip) {
            $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->get('/inspect?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
                ->assertStatus(403)
                ->assertHeader('X-Laravel-Waf-Blocked', 'true');
        }

        self::assertSame(0, $decisionSink->blocks);
    }

    public function test_blocked_json_responses_keep_their_public_shapes(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.140'])
            ->getJson('/inspect?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
            ->assertStatus(403)
            ->assertExactJson(['message' => 'Request blocked.']);

        $this->getJson('/_waf/blocked')
            ->assertStatus(403)
            ->assertExactJson([
                'message' => 'Request blocked.',
                'blocked' => true,
            ]);

        $this->withHeaders(['X-Livewire' => 'true'])
            ->getJson('/_waf/blocked?serverMemo%5Bid%5D=test-component')
            ->assertStatus(403)
            ->assertExactJson([
                'message' => 'Request blocked.',
                'blocked' => true,
            ]);
    }

    public function test_blocked_html_is_rendered_from_the_shared_package_template(): void
    {
        config()->set('laravel-waf.challenge.blocked_title', 'Access <stopped>.');
        config()->set('laravel-waf.challenge.blocked_message', 'Matched the "production" policy.');

        $template = file_get_contents(dirname(__DIR__, 2).'/resources/pages/blocked.html');
        self::assertIsString($template);
        self::assertStringContainsString('<!--@@BLOCKED_TITLE_START@@-->', $template);
        self::assertStringContainsString('@@BLOCKED_REQUEST_ID@@', $template);

        $response = $this->get('/_waf/blocked')
            ->assertStatus(403)
            ->assertSee('Access &lt;stopped&gt;.', false)
            ->assertSee('Matched the &quot;production&quot; policy.', false)
            ->assertDontSee('@@BLOCKED_TITLE_START@@', false)
            ->assertDontSee('@@BLOCKED_REQUEST_ID@@', false);

        $requestId = $response->headers->get('X-Request-ID');
        self::assertIsString($requestId);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $requestId);
        $response->assertSee($requestId, false);
    }

    public function test_sql_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.41'])
            ->get('/inspect?q=1%20UNION%20SELECT%20password%20FROM%20users')
            ->assertStatus(403);
    }

    public function test_sql_server_variable_probes_are_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.65'])
            ->get('/inspect?q=select%20%40%40version')
            ->assertStatus(403);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.65'])
            ->get('/inspect?q=%40%40datadir')
            ->assertStatus(403);
    }

    public function test_livewire_sql_injection_redirects_to_the_top_level_blocked_page(): void
    {
        $this->app['url']->forceRootUrl('https://configured-origin.example');
        config()->set('laravel-waf.agent.enabled', true);
        config()->set('laravel-waf.agent.auto_block_on_finding', true);
        $decisionSink = new RecordingDecisionSink();
        app()->instance(DecisionSink::class, $decisionSink);

        $snapshot = json_encode([
            'data' => ['email' => '=1 UNION SELECT password FROM users'],
            'memo' => ['id' => 'test-component', 'name' => 'login', 'children' => []],
            'checksum' => 'test-checksum',
        ], JSON_THROW_ON_ERROR);
        $server = [
            'REMOTE_ADDR' => '203.0.113.55',
            'SCRIPT_NAME' => '/app/index.php',
            'SCRIPT_FILENAME' => '/var/www/app/index.php',
        ];

        $response = $this->withServerVariables($server)
            ->withHeaders(['X-Livewire' => 'true'])
            ->postJson('/app/inspect', [
                'components' => [[
                    'snapshot' => $snapshot,
                    'updates' => [],
                    'calls' => [],
                ]],
            ]);

        $response->assertOk()
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertJsonPath('components.0.effects.redirect', '/app/_waf/blocked');
        self::assertSame(1, $decisionSink->blocks);

        $this->withServerVariables($server)->get('/app/_waf/blocked')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertSee('Why have I been blocked?');

        $serverMemo = [
            'data' => ['email' => '=1 UNION SELECT password FROM users'],
            'checksum' => 'test-checksum',
        ];

        $server['REMOTE_ADDR'] = '203.0.113.56';
        $legacyResponse = $this->withServerVariables($server)
            ->withHeaders(['X-Livewire' => 'true'])
            ->postJson('/app/inspect', [
                'fingerprint' => ['id' => 'test-component', 'name' => 'login', 'locale' => 'en'],
                'serverMemo' => $serverMemo,
                'updates' => [],
            ]);
        $legacyResponse->assertOk()
            ->assertJsonPath('effects.redirect', '/app/_waf/blocked')
            ->assertJsonPath('serverMemo.data.email', '=1 UNION SELECT password FROM users');
    }

    public function test_rfi_is_blocked_for_a_file_like_parameter(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])
            ->get('/inspect?file=https%3A%2F%2Fevil.test%2Fpayload.txt')
            ->assertStatus(403);
    }

    public function test_public_return_urls_are_not_misclassified_as_rfi(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])
            ->get('/inspect?redirect=https%3A%2F%2Fqa.bserv.dev%2Fcheckout&url=https%3A%2F%2Fqa.bserv.dev%2Fcheckout')
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_lfi_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.43'])
            ->get('/inspect?file=..%2F..%2Fetc%2Fpasswd')
            ->assertStatus(403);
    }

    public function test_uploaded_file_names_are_inspected(): void
    {
        // Browsers control the raw client name; simulate a traversal payload.
        $file = \Illuminate\Http\UploadedFile::fake()->createWithContent('shell.php', 'x');
        $originalName = new \ReflectionProperty(
            \Symfony\Component\HttpFoundation\File\UploadedFile::class,
            'originalName',
        );
        $originalName->setAccessible(true);
        $originalName->setValue($file, '../../../shell.php');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.61'])
            ->post('/inspect', ['upload' => $file])
            ->assertStatus(403);
    }

    public function test_every_uploaded_file_name_in_a_multipart_request_is_inspected(): void
    {
        $benign = \Illuminate\Http\UploadedFile::fake()->createWithContent('report.pdf', 'x');
        $malicious = \Illuminate\Http\UploadedFile::fake()->createWithContent('shell.php', 'x');
        $originalName = new \ReflectionProperty(
            \Symfony\Component\HttpFoundation\File\UploadedFile::class,
            'originalName',
        );
        $originalName->setAccessible(true);
        $originalName->setValue($malicious, '../../../shell.php');

        // The malicious name arrives first and must not be overwritten by
        // the benign upload that follows it.
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.63'])
            ->post('/inspect', ['uploads' => [$malicious, $benign]])
            ->assertStatus(403);
    }

    public function test_traversal_in_the_client_relative_upload_path_is_inspected(): void
    {
        // Real browsers send "C:\..\..\shell.php" or "../../shell.php";
        // Symfony strips the directory from getClientOriginalName() and keeps
        // it in getClientOriginalPath(), which must be inspected too.
        $temp = tempnam(sys_get_temp_dir(), 'laravel-waf-test');
        self::assertIsString($temp);
        $file = new class($temp, 'shell.php', null, UPLOAD_ERR_OK, true) extends \Illuminate\Http\UploadedFile {
            public function getClientOriginalName(): string
            {
                return 'shell.php';
            }

            public function getClientOriginalPath(): string
            {
                return '../../../shell.php';
            }
        };

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.66'])
            ->post('/inspect', ['upload' => $file])
            ->assertStatus(403);
    }

    public function test_uploads_beyond_the_configured_depth_cap_are_ignored(): void
    {
        config()->set('laravel-waf.rules.input.max_depth', 2);

        $temp = tempnam(sys_get_temp_dir(), 'laravel-waf-test');
        self::assertIsString($temp);
        $file = new class($temp, 'shell.php', null, UPLOAD_ERR_OK, true) extends \Illuminate\Http\UploadedFile {
            public function getClientOriginalName(): string
            {
                return 'shell.php';
            }

            public function getClientOriginalPath(): string
            {
                return '../../../shell.php';
            }
        };

        // Four levels deep: the walker must stop before reaching the payload.
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.67'])
            ->post('/inspect', ['a' => ['b' => ['c' => ['d' => $file]]]])
            ->assertOk()
            ->assertContent('ok');

        // The same payload one level deep stays inside the bound and is caught.
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.68'])
            ->post('/inspect', ['shallow' => $file])
            ->assertStatus(403);
    }

    public function test_doubly_encoded_ssrf_targets_are_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.64'])
            ->get('/inspect?url=http%253A%252F%252F127.0.0.1%252Fadmin')
            ->assertStatus(403);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.64'])
            ->get('/inspect?url=http%3A%2F%2F169.254.169.254%2Fmeta')
            ->assertStatus(403);
    }

    public function test_benign_uploaded_file_names_pass(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.62'])
            ->post('/inspect', [
                'upload' => \Illuminate\Http\UploadedFile::fake()->createWithContent('report-2026.pdf', 'x'),
            ])
            ->assertOk()
            ->assertContent('ok');
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

    public function test_crlf_rule_allows_a_legitimate_trailing_newline_in_a_public_key(): void
    {
        $request = Request::create('/inspect', 'POST', [
            'public_key' => "ssh-ed25519 AAAA customer\n",
        ]);
        $finding = (new CrLfRule(new RequestInputCollector()))->inspect($request);

        self::assertNull($finding);
    }

    public function test_waf_allows_a_legitimate_trailing_newline_in_a_public_key(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.69'])
            ->post('/inspect', [
                'public_key' => "ssh-ed25519 AAAA customer\n",
            ])
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_crlf_rule_blocks_header_termination_without_a_header_name(): void
    {
        $request = Request::create('/inspect', 'POST', [
            'next' => "safe\r\n\r\nbody",
        ]);
        $finding = (new CrLfRule(new RequestInputCollector()))->inspect($request);

        self::assertNotNull($finding);
    }

    public function test_ssrf_to_a_loopback_address_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.54'])
            ->get('/inspect?url=http%3A%2F%2F127.0.0.1%2Fadmin')
            ->assertStatus(403);
    }

    public function test_ssrf_does_not_misclassify_nested_domain_fields(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.58'])
            ->post('/inspect', ['domains' => [['years' => '1 year']]])
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_findings_can_be_logged_without_blocking(): void
    {
        config()->set('laravel-waf.rules.mode', 'log');
        config()->set('laravel-waf.agent.enabled', true);
        config()->set('laravel-waf.agent.auto_block_on_finding', true);
        $decisionSink = new RecordingDecisionSink();
        app()->instance(DecisionSink::class, $decisionSink);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.44'])
            ->get('/inspect?name=%3Cscript%3E')
            ->assertOk()
            ->assertContent('ok');

        self::assertSame(0, $decisionSink->blocks);
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

final class RecordingDecisionSink implements DecisionSink
{
    public int $blocks = 0;

    public function block(string $ip, int $ttlSeconds, string $reason): void
    {
        $this->blocks++;
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

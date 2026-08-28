<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

final class DdosProtectionTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->middlewareGroup('waf-login-group', ['laravel-waf.login']);

        Route::middleware(DdosProtection::class)
            ->get('/limited', static fn () => response('ok'))
            ->name('limited');

        Route::middleware(DdosProtection::class)
            ->post('/livewire/update', static fn () => response()->json(['ok' => true]))
            ->name('livewire.update');

        Route::middleware([DdosProtection::class, 'laravel-waf.login'])
            ->post('/protected-login', static fn () => response('logged-in'))
            ->name('protected-login');

        Route::middleware([DdosProtection::class, 'waf-login-group'])
            ->post('/group-protected-login', static fn () => response('logged-in'))
            ->name('group-protected-login');

        Route::middleware([DdosProtection::class, 'waf-login-group'])
            ->get('/group-protected-login', static fn () => response('login-form'))
            ->name('group-protected-login.form');

        Route::middleware([DdosProtection::class, 'waf-login-group'])
            ->withoutMiddleware('laravel-waf.login')
            ->post('/group-excluded-login', static fn () => response('logged-in'))
            ->name('group-excluded-login');

        Route::middleware('laravel-waf.login')
            ->post('/global-protected-login', static fn () => response('logged-in'))
            ->name('global-protected-login');

        Route::middleware('laravel-waf.login')
            ->post('/global-controller-login', [DdosControllerConstructionProbe::class, 'store'])
            ->name('global-controller-login');

        Route::middleware('laravel-waf.login')
            ->post('/global-routing-cost/{account}', static fn () => response('logged-in'))
            ->name('global-routing-cost');

        Route::get('/global-limited', static fn () => response('ok'))
            ->name('global-limited');
    }

    public function test_burst_limit_blocks_a_flood_inside_the_short_window(): void
    {
        config()->set('laravel-waf.ddos.burst', [
            'enabled' => true,
            'max_attempts' => 2,
            'decay_seconds' => 5,
        ]);
        config()->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 100, 'decay_seconds' => 60]]);

        $server = ['REMOTE_ADDR' => '203.0.113.120'];
        $this->withServerVariables($server)->get('/limited')->assertOk();
        $this->withServerVariables($server)->get('/limited')->assertOk();

        $this->withServerVariables($server)
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('Retry-After');
    }

    public function test_burst_limit_can_be_disabled(): void
    {
        config()->set('laravel-waf.ddos.burst.enabled', false);
        config()->set('laravel-waf.ddos.burst.max_attempts', 1);

        $server = ['REMOTE_ADDR' => '203.0.113.121'];
        $this->withServerVariables($server)->get('/limited')->assertOk();
        $this->withServerVariables($server)->get('/limited')->assertOk();
    }

    public function test_rejecting_bucket_reports_its_own_limit_header(): void
    {
        // The global bucket rejects first; its quota must be the one exposed.
        config()->set('laravel-waf.ddos.global', ['max_attempts' => 1, 'decay_seconds' => 60]);
        config()->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 100, 'decay_seconds' => 60]]);

        $server = ['REMOTE_ADDR' => '203.0.113.122'];
        $this->withServerVariables($server)->get('/limited')->assertOk();

        $this->withServerVariables($server)
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('X-RateLimit-Limit', '1')
            ->assertHeader('X-RateLimit-Remaining', '0');
    }

    public function test_a_stale_counter_does_not_extend_the_lockout_window(): void
    {
        // A cache can retain the counter after its timer entry expired; the
        // limiter must reset it instead of rejecting and starting a fresh
        // lockout window from the stale count.
        $key = \BillingServ\LaravelWaf\Support\RateLimitKey::for('route', '203.0.113.123', 'limited');
        cache()->store()->put($key, 999, 3600);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.123'])
            ->get('/limited')
            ->assertOk();
    }

    public function test_route_limit_returns_too_many_requests(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk()
            ->assertHeader('X-RateLimit-Remaining', '1');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk()
            ->assertHeader('X-RateLimit-Remaining', '0');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeader('X-RateLimit-Remaining', '0');
    }

    public function test_route_limit_can_issue_one_agent_block_decision(): void
    {
        config()->set('laravel-waf.agent.enabled', true);
        config()->set('laravel-waf.agent.auto_block_on_limit', true);
        $decisionSink = new class implements DecisionSink {
            public int $blocks = 0;

            public function block(string $ip, int $ttlSeconds, string $reason): void
            {
                $this->blocks++;
            }
        };
        app()->instance(DecisionSink::class, $decisionSink);

        $server = ['REMOTE_ADDR' => '203.0.113.110'];
        $this->withServerVariables($server)->get('/limited')->assertOk();
        $this->withServerVariables($server)->get('/limited')->assertOk();
        $this->withServerVariables($server)->get('/limited')->assertStatus(429);
        $this->withServerVariables($server)->get('/limited')->assertStatus(429);

        self::assertSame(1, $decisionSink->blocks);
    }

    public function test_different_clients_have_independent_limits(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.11'])
            ->get('/limited')
            ->assertOk();
    }

    public function test_adaptive_mode_challenges_new_clients_during_site_wide_traffic_pressure(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.ddos.adaptive.enabled', true);
        config()->set('laravel-waf.ddos.adaptive.challenge_after', 2);
        config()->set('laravel-waf.ddos.adaptive.window_seconds', 60);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.12'])->get('/limited')->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.13'])->get('/limited')->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.14'])
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');

        $pass = app(ChallengeTokenManager::class)->issuePass('203.0.113.15', 600);
        self::assertNotNull($pass);

        $this->withUnencryptedCookie('laravel_waf_challenge', $pass)
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.15'])
            ->get('/limited')
            ->assertOk();
    }

    public function test_authenticated_agent_gate_marker_forces_the_browser_challenge(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.agent.gate.enabled', true);
        config()->set('laravel-waf.agent.gate.token', str_repeat('g', 32));

        $this->withHeader('X-Laravel-Waf-Gate', str_repeat('g', 32))
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.17'])
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
    }

    public function test_agent_gate_allows_requests_without_a_challenge_marker(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.agent.gate.enabled', true);
        config()->set('laravel-waf.agent.gate.token', str_repeat('g', 32));

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.18'])
            ->get('/limited')
            ->assertOk();
    }

    public function test_invalid_agent_gate_marker_fails_closed(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.agent.gate.enabled', true);
        config()->set('laravel-waf.agent.gate.token', str_repeat('g', 32));

        $this->withHeader('X-Laravel-Waf-Gate', 'attacker-controlled')
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.181'])
            ->get('/limited')
            ->assertStatus(503);
    }

    public function test_passed_browser_ignores_an_agent_gate_marker(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.agent.gate.enabled', true);
        config()->set('laravel-waf.agent.gate.token', str_repeat('g', 32));

        $pass = app(ChallengeTokenManager::class)->issuePass('203.0.113.19', 600);
        self::assertNotNull($pass);

        $this->withHeader('X-Laravel-Waf-Gate', str_repeat('g', 32))
            ->withUnencryptedCookie('laravel_waf_challenge', $pass)
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.19'])
            ->get('/limited')
            ->assertOk();
    }

    public function test_challenge_mode_returns_a_challenge_response(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.enabled', true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited');
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required')
            ->assertSee('Additional verification required');
    }

    public function test_login_protection_prevents_generic_ddos_challenges_on_login_submissions(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');

        $server = ['REMOTE_ADDR' => '203.0.113.23'];
        $this->withServerVariables($server)
            ->post('/protected-login', ['email' => 'user@example.test'])
            ->assertOk();
        $this->withServerVariables($server)
            ->post('/protected-login', ['email' => 'user@example.test'])
            ->assertOk();
        $this->withServerVariables($server)
            ->post('/protected-login', ['email' => 'user@example.test'])
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertDontSee('Checking your browser');
    }

    #[DataProvider('disabledLoginProtectionChallengeCases')]
    public function test_disabled_login_protection_does_not_suppress_ddos_challenges(string $source, string $ip): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.login.enabled', false);
        $server = ['REMOTE_ADDR' => $ip];

        if ($source === 'adaptive') {
            config()->set('laravel-waf.ddos.adaptive.enabled', true);
            config()->set('laravel-waf.ddos.adaptive.challenge_after', 1);
            config()->set('laravel-waf.ddos.adaptive.window_seconds', 60);
            $this->withServerVariables($server)->post('/protected-login')->assertOk();
        } elseif ($source === 'agent_gate') {
            config()->set('laravel-waf.agent.gate.enabled', true);
            config()->set('laravel-waf.agent.gate.token', str_repeat('g', 32));
        } else {
            $this->withServerVariables($server)->post('/protected-login')->assertOk();
            $this->withServerVariables($server)->post('/protected-login')->assertOk();
        }

        $request = $this->withServerVariables($server);
        if ($source === 'agent_gate') {
            $request = $request->withHeader('X-Laravel-Waf-Gate', str_repeat('g', 32));
        }

        $request->post('/protected-login')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
    }

    public static function disabledLoginProtectionChallengeCases(): array
    {
        return [
            'generic bucket' => ['generic', '203.0.113.40'],
            'adaptive pressure' => ['adaptive', '203.0.113.41'],
            'agent gate' => ['agent_gate', '203.0.113.42'],
        ];
    }

    public function test_login_protection_in_a_middleware_group_prevents_generic_ddos_challenges(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');

        $server = ['REMOTE_ADDR' => '203.0.113.24'];
        $this->withServerVariables($server)->post('/group-protected-login')->assertOk();
        $this->withServerVariables($server)->post('/group-protected-login')->assertOk();

        $this->withServerVariables($server)
            ->post('/group-protected-login')
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeaderMissing('X-Laravel-Waf-Challenge')
            ->assertDontSee('Checking your browser');
    }

    public function test_safe_login_form_route_in_a_middleware_group_can_receive_a_challenge(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');

        $server = ['REMOTE_ADDR' => '203.0.113.36'];
        $this->withServerVariables($server)->get('/group-protected-login')->assertOk();
        $this->withServerVariables($server)->get('/group-protected-login')->assertOk();

        $this->withServerVariables($server)
            ->get('/group-protected-login')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
    }

    public function test_excluded_login_middleware_does_not_suppress_a_generic_ddos_challenge(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');

        $server = ['REMOTE_ADDR' => '203.0.113.25'];
        $this->withServerVariables($server)->post('/group-excluded-login')->assertOk();
        $this->withServerVariables($server)->post('/group-excluded-login')->assertOk();

        $this->withServerVariables($server)
            ->post('/group-excluded-login')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required')
            ->assertSee('Checking your browser');
    }

    public function test_global_waf_detects_login_protection_before_route_dispatch(): void
    {
        $this->app->make(HttpKernel::class)->pushMiddleware(WafProtection::class);
        config()->set('laravel-waf.ddos.mode', 'challenge');

        $server = ['REMOTE_ADDR' => '203.0.113.26'];
        $this->withServerVariables($server)->post('/global-protected-login')->assertOk();
        $this->withServerVariables($server)->post('/global-protected-login')->assertOk();

        $this->withServerVariables($server)
            ->post('/global-protected-login')
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeaderMissing('X-Laravel-Waf-Challenge')
            ->assertDontSee('Checking your browser');
    }

    public function test_global_waf_rejects_a_flood_without_constructing_the_route_controller(): void
    {
        $this->app->make(HttpKernel::class)->pushMiddleware(WafProtection::class);
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.ddos.global', ['max_attempts' => 1, 'decay_seconds' => 60]);
        config()->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 100, 'decay_seconds' => 60]]);

        $ip = '203.0.113.28';
        DdosControllerConstructionProbe::$constructions = 0;
        $limiter = $this->app->make(RateLimiter::class);
        $key = RateLimitKey::for('global', $ip);
        $limiter->hit($key, 60);

        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post('/global-controller-login')
            ->assertStatus(429)
            ->assertHeaderMissing('X-Laravel-Waf-Challenge');

        self::assertSame(0, DdosControllerConstructionProbe::$constructions);

        $limiter->clear($key);
        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post('/global-controller-login')
            ->assertOk();

        self::assertSame(1, DdosControllerConstructionProbe::$constructions);
    }

    public function test_global_waf_does_not_match_the_route_early_in_reject_mode(): void
    {
        $this->app->make(HttpKernel::class)->pushMiddleware(WafProtection::class);
        config()->set('laravel-waf.ddos.mode', 'reject');
        config()->set('laravel-waf.ddos.global', ['max_attempts' => 1, 'decay_seconds' => 60]);
        config()->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 100, 'decay_seconds' => 60]]);

        $ip = '203.0.113.29';
        $route = Route::getRoutes()->getByName('global-routing-cost');
        self::assertNotNull($route);
        self::assertFalse($route->hasParameters());
        $this->app->make(RateLimiter::class)->hit(RateLimitKey::for('global', $ip), 60);

        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post('/global-routing-cost/customer-1')
            ->assertStatus(429);

        self::assertFalse($route->hasParameters());
    }

    public function test_global_waf_does_not_match_the_route_early_when_challenges_are_disabled(): void
    {
        $this->app->make(HttpKernel::class)->pushMiddleware(WafProtection::class);
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.enabled', false);
        config()->set('laravel-waf.ddos.global', ['max_attempts' => 1, 'decay_seconds' => 60]);
        config()->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 100, 'decay_seconds' => 60]]);

        $ip = '203.0.113.30';
        $route = Route::getRoutes()->getByName('global-routing-cost');
        self::assertNotNull($route);
        self::assertFalse($route->hasParameters());
        $this->app->make(RateLimiter::class)->hit(RateLimitKey::for('global', $ip), 60);

        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post('/global-routing-cost/customer-2')
            ->assertStatus(429);

        self::assertFalse($route->hasParameters());
    }

    public function test_livewire_challenge_navigates_to_a_top_level_page_and_returns_to_the_form(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        $this->app->instance(ChallengeVerifier::class, new class implements ChallengeVerifier {
            public function verify(mixed $payload): bool
            {
                return $payload === 'valid-payload';
            }
        });

        $snapshot = json_encode([
            'data' => [],
            'memo' => ['id' => 'login-component', 'name' => 'login', 'children' => []],
            'checksum' => 'test-checksum',
        ], JSON_THROW_ON_ERROR);
        $request = [
            'components' => [[
                'snapshot' => $snapshot,
                'updates' => [],
                'calls' => [],
            ]],
        ];
        $server = ['REMOTE_ADDR' => '203.0.113.22'];
        $headers = [
            'X-Livewire' => 'true',
            'Referer' => 'http://localhost/login',
        ];

        $this->withHeaders($headers)->withServerVariables($server)->postJson('/livewire/update', $request);
        $this->withHeaders($headers)->withServerVariables($server)->postJson('/livewire/update', $request);

        $response = $this->withHeaders($headers)
            ->withServerVariables($server)
            ->postJson('/livewire/update', $request);

        $response->assertOk()->assertHeader('X-Laravel-Waf-Challenge', 'required');
        $redirect = $response->json('components.0.effects.redirect');
        self::assertIsString($redirect);
        self::assertStringContainsString('/_waf/challenge?', $redirect);

        $page = $this->get(parse_url($redirect, PHP_URL_PATH).'?'.parse_url($redirect, PHP_URL_QUERY));
        $page->assertStatus(429)
            ->assertSee('altcha-widget')
            ->assertSee('Checking your browser');

        preg_match('/name="_waf_challenge" value="([^"]+)"/', $page->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);

        $this->withServerVariables($server)
            ->post('/_waf/challenge/verify', [
                '_waf_challenge' => $matches[1],
                'altcha' => 'valid-payload',
            ])
            ->assertRedirect('/login')
            ->assertStatus(303);
    }

    #[DataProvider('referrerPortCases')]
    public function test_livewire_return_url_requires_the_same_effective_port(string $referer, string $expectedReturnTo): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost:8080/altcha/challenge');

        $snapshot = json_encode([
            'data' => [],
            'memo' => ['id' => 'login-component', 'name' => 'login', 'children' => []],
            'checksum' => 'test-checksum',
        ], JSON_THROW_ON_ERROR);
        $request = [
            'components' => [[
                'snapshot' => $snapshot,
                'updates' => [],
                'calls' => [],
            ]],
        ];
        $ip = '203.0.113.37';
        $server = [
            'REMOTE_ADDR' => $ip,
            'HTTP_HOST' => 'localhost:8080',
            'SERVER_PORT' => '8080',
        ];
        $headers = [
            'Host' => 'localhost:8080',
            'X-Livewire' => 'true',
            'Referer' => $referer,
        ];
        $requestUrl = 'http://localhost:8080/livewire/update';

        $this->withHeaders($headers)->withServerVariables($server)->postJson($requestUrl, $request);
        $this->withHeaders($headers)->withServerVariables($server)->postJson($requestUrl, $request);
        $response = $this->withHeaders($headers)
            ->withServerVariables($server)
            ->postJson($requestUrl, $request);

        $response->assertOk();
        $redirect = $response->json('components.0.effects.redirect');
        self::assertIsString($redirect);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        self::assertIsString($query['_waf_challenge'] ?? null);
        self::assertSame(
            $expectedReturnTo,
            $this->app->make(ChallengeTokenManager::class)->requestReturnTo($query['_waf_challenge'], $ip),
        );
    }

    public static function referrerPortCases(): array
    {
        return [
            'same non-default port' => ['http://localhost:8080/login?next=account', '/login?next=account'],
            'different explicit port' => ['http://localhost:9090/login?next=account', '/'],
            'implicit default port' => ['http://localhost/login?next=account', '/'],
            'oversized encoded token' => ['http://localhost:8080/'.str_repeat('"', 2047), '/'],
        ];
    }

    public function test_json_altcha_challenge_does_not_require_a_widget_url(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', null);

        $server = ['REMOTE_ADDR' => '203.0.113.31'];
        $this->withServerVariables($server)->getJson('/limited')->assertOk();
        $this->withServerVariables($server)->getJson('/limited')->assertOk();

        $this->withServerVariables($server)
            ->getJson('/limited')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required')
            ->assertJsonPath('challenge', true)
            ->assertJsonPath('provider', 'altcha')
            ->assertJsonPath('verification_url', 'http://localhost/_waf/challenge/verify')
            ->assertJsonStructure(['challenge_token']);
    }

    public function test_html_altcha_challenge_still_requires_a_widget_url(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', null);

        $server = ['REMOTE_ADDR' => '203.0.113.32'];
        $this->withServerVariables($server)->get('/limited')->assertOk();
        $this->withServerVariables($server)->get('/limited')->assertOk();

        $this->withServerVariables($server)
            ->get('/limited')
            ->assertStatus(503)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required')
            ->assertSee('Verification temporarily unavailable');
    }

    public function test_json_altcha_unavailable_response_is_json_when_signing_is_unconfigured(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.cookie_secret', null);
        config()->set('app.key', null);

        $server = ['REMOTE_ADDR' => '203.0.113.33'];
        $this->withServerVariables($server)->getJson('/limited')->assertOk();
        $this->withServerVariables($server)->getJson('/limited')->assertOk();

        $this->withServerVariables($server)
            ->getJson('/limited')
            ->assertStatus(503)
            ->assertHeader('Content-Type', 'application/json')
            ->assertJsonPath('message', 'Challenge verification is temporarily unavailable.');
    }

    public function test_json_altcha_unavailable_response_is_json_when_verification_route_is_missing(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.verify_route', 'missing-challenge-route');

        $server = ['REMOTE_ADDR' => '203.0.113.34'];
        $this->withServerVariables($server)->getJson('/limited')->assertOk();
        $this->withServerVariables($server)->getJson('/limited')->assertOk();

        $this->withServerVariables($server)
            ->getJson('/limited')
            ->assertStatus(503)
            ->assertHeader('Content-Type', 'application/json')
            ->assertJsonPath('message', 'Challenge verification is temporarily unavailable.');
    }

    #[DataProvider('livewireUnavailableCases')]
    public function test_livewire_altcha_unavailable_response_is_json_with_a_wildcard_accept_header(array $configuration): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        foreach ($configuration as $key => $value) {
            config()->set($key, $value);
        }

        $request = [
            'components' => [[
                'snapshot' => '{}',
                'updates' => [],
                'calls' => [],
            ]],
        ];
        $server = ['REMOTE_ADDR' => '203.0.113.35'];
        $headers = [
            'Accept' => '*/*',
            'X-Livewire' => 'true',
        ];
        $this->withServerVariables($server)->postJson('/livewire/update', $request, $headers)->assertOk();
        $this->withServerVariables($server)->postJson('/livewire/update', $request, $headers)->assertOk();

        $this->withServerVariables($server)
            ->postJson('/livewire/update', $request, $headers)
            ->assertStatus(503)
            ->assertHeader('Content-Type', 'application/json')
            ->assertJsonPath('message', 'Challenge verification is temporarily unavailable.');
    }

    public static function livewireUnavailableCases(): array
    {
        return [
            'missing signing secret' => [[
                'laravel-waf.challenge.cookie_secret' => null,
                'app.key' => null,
            ]],
            'missing verification route' => [[
                'laravel-waf.challenge.verify_route' => 'missing-challenge-route',
            ]],
            'missing widget URL' => [[
                'laravel-waf.challenge.altcha.challenge_url' => null,
            ]],
        ];
    }

    public function test_livewire_challenge_accepts_a_long_signed_return_url(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        $this->app->instance(ChallengeVerifier::class, new class implements ChallengeVerifier {
            public function verify(mixed $payload): bool
            {
                return $payload === 'valid-payload';
            }
        });

        $snapshot = json_encode([
            'data' => [],
            'memo' => ['id' => 'login-component', 'name' => 'login', 'children' => []],
            'checksum' => 'test-checksum',
        ], JSON_THROW_ON_ERROR);
        $request = [
            'components' => [[
                'snapshot' => $snapshot,
                'updates' => [],
                'calls' => [],
            ]],
        ];
        $server = ['REMOTE_ADDR' => '203.0.113.27'];
        $returnTo = str_repeat('/a', 999);
        $headers = [
            'X-Livewire' => 'true',
            'Referer' => 'http://localhost'.$returnTo,
        ];

        $this->withHeaders($headers)->withServerVariables($server)->postJson('/livewire/update', $request);
        $this->withHeaders($headers)->withServerVariables($server)->postJson('/livewire/update', $request);
        $response = $this->withHeaders($headers)
            ->withServerVariables($server)
            ->postJson('/livewire/update', $request);

        $response->assertOk()->assertHeader('X-Laravel-Waf-Challenge', 'required');
        $redirect = $response->json('components.0.effects.redirect');
        self::assertIsString($redirect);
        self::assertGreaterThan(2048, strlen($redirect));
        self::assertStringContainsString('/_waf/challenge?', $redirect);

        $page = $this->withServerVariables($server)
            ->get(parse_url($redirect, PHP_URL_PATH).'?'.parse_url($redirect, PHP_URL_QUERY));
        $page->assertStatus(429)->assertSee('Checking your browser');

        preg_match('/name="_waf_challenge" value="([^"]+)"/', $page->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);

        $this->withServerVariables($server)
            ->post('/_waf/challenge/verify', [
                '_waf_challenge' => $matches[1],
                'altcha' => 'valid-payload',
            ])
            ->assertRedirect($returnTo)
            ->assertStatus(303);
    }

    public function test_altcha_challenge_can_run_and_submit_automatically(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        config()->set('laravel-waf.challenge.altcha.auto', 'onload');
        config()->set('laravel-waf.challenge.altcha.auto_submit', true);
        config()->set('laravel-waf.challenge.altcha.display', 'invisible');

        $server = ['REMOTE_ADDR' => '203.0.113.16'];
        $this->withServerVariables($server)->get('/limited');
        $this->withServerVariables($server)->get('/limited');

        $response = $this->withServerVariables($server)->get('/limited');

        $response
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required')
            ->assertSee('auto="onload"', false)
            ->assertSee('display="invisible"', false)
            ->assertSee('class="verification-form is-automatic"', false)
            ->assertSee('class="verification-layout"', false)
            ->assertSee('class="verification-spinner"', false)
            ->assertSee('data-altcha-visibility="concealed"', false)
            ->assertSee('data-verification-label', false)
            ->assertSee('This usually takes only a few seconds.')
            ->assertSee('This check is automatic. You will continue as soon as it is complete.')
            ->assertSee('Reload the page')
            ->assertSee('Performance & security by')
            ->assertSee('https://www.billingserv.com', false)
            ->assertDontSee('class="verification-submit"', false)
            ->assertDontSee('Laravel WAF')
            ->assertSee('statechange', false)
            ->assertSee('event.detail.payload', false)
            ->assertSee('data-altcha-payload', false)
            ->assertSee('input.name=fieldName', false)
            ->assertSee('widget.setAttribute("display","standard")', false)
            ->assertSee('form.submit()', false);

        $requestId = $response->headers->get('X-Request-ID');
        self::assertIsString($requestId);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $requestId);
        $response->assertSee($requestId);
    }

    public function test_challenge_cookie_is_excluded_from_laravel_cookie_encryption(): void
    {
        $middlewareClass = 'Illuminate\\Cookie\\Middleware\\EncryptCookies';
        if (!class_exists($middlewareClass)) {
            self::markTestSkipped('Laravel cookie middleware is not installed.');
        }

        $middleware = new $middlewareClass(app('encrypter'));

        self::assertTrue($middleware->isDisabled('laravel_waf_challenge'));
    }

    public function test_altcha_challenge_can_be_completed_and_returns_a_bounded_pass(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        config()->set('laravel-waf.challenge.altcha.hmac_key', 'test-altcha-secret');
        config()->set('laravel-waf.challenge.cookie_secure', 'auto');

        $server = ['REMOTE_ADDR' => '203.0.113.20'];
        $this->withServerVariables($server)->get('/limited');
        $this->withServerVariables($server)->get('/limited');
        $challenge = $this->withServerVariables($server)->get('/limited');

        $challenge->assertStatus(429)
            ->assertSee('altcha-widget')
            ->assertSee('class="verification-submit"', false)
            ->assertSee('Continue')
            ->assertDontSee('class="verification-form is-automatic"', false)
            ->assertSee('/_waf/challenge/verify');

        preg_match('/name="_waf_challenge" value="([^"]+)"/', $challenge->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);

        $verification = $this->withServerVariables($server)->post('/_waf/challenge/verify', [
            '_waf_challenge' => $matches[1],
            'altcha' => $this->validAltchaPayload(),
        ]);

        $verification->assertRedirect('/limited')->assertStatus(303);
        $cookies = $verification->baseResponse->headers->getCookies();
        self::assertCount(1, $cookies);
        self::assertFalse($cookies[0]->isSecure());

        $this->withUnencryptedCookie($cookies[0]->getName(), $cookies[0]->getValue())
            ->withServerVariables($server)
            ->get('/limited')
            ->assertOk();

        $this->withServerVariables($server)->post('/_waf/challenge/verify', [
            '_waf_challenge' => $matches[1],
            'altcha' => $this->validAltchaPayload(),
        ])->assertStatus(422)
            ->assertSee('Verification failed')
            ->assertSee('The request was not continued.');
    }

    public function test_global_waf_allows_the_internal_challenge_verification_request(): void
    {
        $this->app->make(HttpKernel::class)->pushMiddleware(WafProtection::class);
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.ddos.routes.*.max_attempts', 1);
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        $this->app->instance(ChallengeVerifier::class, new class implements ChallengeVerifier {
            public function verify(mixed $payload): bool
            {
                return $payload === 'valid-payload';
            }
        });

        $server = ['REMOTE_ADDR' => '203.0.113.21'];
        $this->withServerVariables($server)->get('/global-limited')->assertOk();
        $challenge = $this->withServerVariables($server)->get('/global-limited');

        $challenge->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
        preg_match('/name="_waf_challenge" value="([^"]+)"/', $challenge->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);

        $verification = $this->withServerVariables($server)->post('/_waf/challenge/verify', [
            '_waf_challenge' => $matches[1],
            'altcha' => 'valid-payload',
        ]);

        $verification->assertRedirect('/global-limited')->assertStatus(303);
        $cookies = $verification->baseResponse->headers->getCookies();
        self::assertCount(1, $cookies);

        $this->withUnencryptedCookie($cookies[0]->getName(), $cookies[0]->getValue())
            ->withServerVariables($server)
            ->get('/global-limited')
            ->assertOk();
    }

    public function test_opt_in_test_query_parameter_displays_the_blocked_page_in_production(): void
    {
        $this->app['env'] = 'production';
        config()->set('laravel-waf.testing.enabled', true);
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        config()->set('laravel-waf.challenge.altcha.hmac_key', 'test-altcha-secret');

        $server = ['REMOTE_ADDR' => '203.0.113.30'];
        $response = $this->withServerVariables($server)->get('/limited?test');

        $response
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertSee('class="blocked-layout"', false)
            ->assertSee('Sorry, you’ve been blocked from viewing this page.')
            ->assertSee('Why have I been blocked?')
            ->assertSee('What can I do to resolve this?')
            ->assertSee('Request ID:')
            ->assertSee('Performance & security by')
            ->assertSee('class="blocked-link" href="/"', false)
            ->assertSee('https://www.billingserv.com', false)
            ->assertSee('BillingServ')
            ->assertDontSee('Additional verification required')
            ->assertDontSee('Verification failed')
            ->assertDontSee('Laravel WAF')
            ->assertDontSee('<altcha-widget');

        $requestId = $response->headers->get('X-Request-ID');
        self::assertIsString($requestId);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $requestId);
        $response->assertSee($requestId);
    }

    public function test_test_query_parameter_is_ignored_in_production_until_enabled(): void
    {
        $this->app['env'] = 'production';

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.31'])
            ->get('/limited?test')
            ->assertOk()
            ->assertDontSee('class="blocked-layout"', false);
    }

    public function test_opt_in_test_query_parameter_keeps_the_blocked_json_shape(): void
    {
        config()->set('laravel-waf.testing.enabled', true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.130'])
            ->getJson('/limited?test')
            ->assertStatus(403)
            ->assertExactJson([
                'message' => 'Request blocked.',
                'blocked' => true,
                'scope' => 'test',
            ]);
    }

    private function validAltchaPayload(): string
    {
        $altchaClass = class_exists('AltchaOrg\\Altcha\\V1\\Altcha')
            ? 'AltchaOrg\\Altcha\\V1\\Altcha'
            : 'AltchaOrg\\Altcha\\Altcha';
        $optionsClass = class_exists('AltchaOrg\\Altcha\\V1\\ChallengeOptions')
            ? 'AltchaOrg\\Altcha\\V1\\ChallengeOptions'
            : 'AltchaOrg\\Altcha\\ChallengeOptions';
        $algorithmClass = class_exists('AltchaOrg\\Altcha\\V1\\Hasher\\Algorithm')
            ? 'AltchaOrg\\Altcha\\V1\\Hasher\\Algorithm'
            : 'AltchaOrg\\Altcha\\Hasher\\Algorithm';
        $altcha = new $altchaClass('test-altcha-secret');
        $challenge = $altcha->createChallenge(new $optionsClass(maxNumber: 1));
        $solution = $altcha->solveChallenge(
            $challenge->challenge,
            $challenge->salt,
            $algorithmClass::from($challenge->algorithm),
            $challenge->maxNumber,
        );

        self::assertNotNull($solution);

        return base64_encode(json_encode([
            'algorithm' => $challenge->algorithm,
            'challenge' => $challenge->challenge,
            'number' => $solution->number,
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
        ], JSON_THROW_ON_ERROR));
    }
}

final class DdosControllerConstructionProbe extends Controller
{
    public static int $constructions = 0;

    public function __construct()
    {
        self::$constructions++;
    }

    public function store()
    {
        return response('logged-in');
    }
}

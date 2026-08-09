<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\Facades\Route;

final class DdosProtectionTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        Route::middleware(DdosProtection::class)
            ->get('/limited', static fn () => response('ok'))
            ->name('limited');

        Route::get('/global-limited', static fn () => response('ok'))
            ->name('global-limited');
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

        $this->withServerVariables($server)
            ->get('/limited')
            ->assertStatus(429)
            ->assertSee('auto="onload"', false)
            ->assertSee('display="invisible"', false)
            ->assertSee('statechange', false)
            ->assertSee('event.detail.payload', false)
            ->assertSee('data-laravel-waf-altcha-payload', false)
            ->assertSee('input.name=fieldName', false)
            ->assertSee('form.submit()', false);
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
            ->assertSee('Verification could not be completed.');
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

    public function test_opt_in_test_query_parameter_displays_the_blocked_page(): void
    {
        config()->set('laravel-waf.testing.enabled', true);
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.theme', 'dark');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        config()->set('laravel-waf.challenge.altcha.hmac_key', 'test-altcha-secret');

        $server = ['REMOTE_ADDR' => '203.0.113.30'];
        $this->withServerVariables($server)
            ->get('/limited?test')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true')
            ->assertSee('theme-dark')
            ->assertSee('Why have I been blocked?')
            ->assertSee('What can I do to resolve this?')
            ->assertDontSee('Additional verification required')
            ->assertDontSee('Verification failed')
            ->assertDontSee('Laravel WAF')
            ->assertDontSee('<altcha-widget');
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

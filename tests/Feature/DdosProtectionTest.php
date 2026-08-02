<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Support\Facades\Route;

final class DdosProtectionTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        Route::middleware(DdosProtection::class)
            ->get('/limited', static fn () => response('ok'))
            ->name('limited');
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

    public function test_different_clients_have_independent_limits(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.11'])
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

    public function test_altcha_challenge_can_be_completed_and_returns_a_bounded_pass(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        config()->set('laravel-waf.challenge.altcha.hmac_key', 'test-altcha-secret');

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

        $this->withUnencryptedCookie($cookies[0]->getName(), $cookies[0]->getValue())
            ->withServerVariables($server)
            ->get('/limited')
            ->assertOk();

        $this->withServerVariables($server)->post('/_waf/challenge/verify', [
            '_waf_challenge' => $matches[1],
            'altcha' => $this->validAltchaPayload(),
        ])->assertStatus(422);
    }

    public function test_opt_in_test_query_parameter_displays_altcha_and_strips_it_after_verification(): void
    {
        config()->set('laravel-waf.testing.enabled', true);
        config()->set('laravel-waf.challenge.provider', 'altcha');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'http://localhost/altcha/challenge');
        config()->set('laravel-waf.challenge.altcha.hmac_key', 'test-altcha-secret');

        $server = ['REMOTE_ADDR' => '203.0.113.30'];
        $challenge = $this->withServerVariables($server)->get('/limited?test');

        $challenge->assertStatus(429)->assertSee('altcha-widget');
        preg_match('/name="_waf_challenge" value="([^"]+)"/', $challenge->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);

        $verification = $this->withServerVariables($server)->post('/_waf/challenge/verify', [
            '_waf_challenge' => $matches[1],
            'altcha' => $this->validAltchaPayload(),
        ]);

        $verification->assertRedirect('/limited')->assertStatus(303);
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

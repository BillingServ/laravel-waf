<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Tests\TestCase;
use BillingServ\LaravelWaf\WafServiceProvider;

final class SharedSecretConfigurationTest extends TestCase
{
    public function test_shared_secret_fills_missing_values_in_an_older_published_configuration(): void
    {
        config()->set('laravel-waf', [
            'secret' => 'shared-waf-secret-with-at-least-32-bytes',
            'challenge' => [
                'cookie_secret' => null,
                'altcha' => ['hmac_key' => null],
            ],
            'agent' => [
                'secret' => null,
                'gate' => ['token' => null],
            ],
        ]);

        (new WafServiceProvider($this->app))->register();

        self::assertSame(
            'shared-waf-secret-with-at-least-32-bytes',
            config('laravel-waf.challenge.cookie_secret'),
        );
        self::assertSame(
            'shared-waf-secret-with-at-least-32-bytes',
            config('laravel-waf.challenge.altcha.hmac_key'),
        );
        self::assertSame(
            'shared-waf-secret-with-at-least-32-bytes',
            config('laravel-waf.agent.secret'),
        );
        self::assertSame(
            'shared-waf-secret-with-at-least-32-bytes',
            config('laravel-waf.agent.gate.token'),
        );
    }
}

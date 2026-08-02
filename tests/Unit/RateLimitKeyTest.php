<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\RateLimitKey;
use PHPUnit\Framework\TestCase;

final class RateLimitKeyTest extends TestCase
{
    public function test_keys_do_not_contain_the_raw_ip_address(): void
    {
        $key = RateLimitKey::for('route', '203.0.113.10', 'limited');

        self::assertStringNotContainsString('203.0.113.10', $key);
        self::assertStringStartsWith('laravel-waf:rate:route:', $key);
    }

    public function test_same_identity_produces_a_stable_key(): void
    {
        self::assertSame(
            RateLimitKey::for('global', '2001:db8::10'),
            RateLimitKey::for('global', '2001:db8::10'),
        );
    }
}

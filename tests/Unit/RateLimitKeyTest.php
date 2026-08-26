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

    public function test_ipv6_addresses_share_one_key_within_the_same_64_prefix(): void
    {
        self::assertSame(
            RateLimitKey::for('global', '2001:db8:abcd:0012::1'),
            RateLimitKey::for('global', '2001:db8:abcd:0012:ffff::9'),
        );

        self::assertNotSame(
            RateLimitKey::for('global', '2001:db8:abcd:0012::1'),
            RateLimitKey::for('global', '2001:db8:abcd:0013::1'),
        );
    }

    public function test_ipv4_mapped_ipv6_uses_the_exact_ipv4_address(): void
    {
        self::assertSame(
            RateLimitKey::for('global', '::ffff:203.0.113.10'),
            RateLimitKey::for('global', '203.0.113.10'),
        );

        self::assertNotSame(
            RateLimitKey::for('global', '::ffff:203.0.113.10'),
            RateLimitKey::for('global', '::ffff:203.0.113.11'),
        );
    }

    public function test_behavior_keys_group_ipv6_by_prefix_and_ipv4_exactly(): void
    {
        self::assertSame(
            RateLimitKey::behavior('2001:db8::1', '404'),
            RateLimitKey::behavior('2001:db8::beef', '404'),
        );

        self::assertNotSame(
            RateLimitKey::behavior('203.0.113.10', '404'),
            RateLimitKey::behavior('203.0.113.11', '404'),
        );
    }
}

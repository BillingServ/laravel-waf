<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\OutboundUrlGuard;
use BillingServ\LaravelWaf\Tests\TestCase;

final class OutboundUrlGuardTest extends TestCase
{
    public function test_private_and_unsafe_urls_are_rejected(): void
    {
        $guard = $this->app->make(OutboundUrlGuard::class);

        self::assertFalse($guard->allows('http://127.0.0.1/admin'));
        self::assertFalse($guard->allows('file:///etc/passwd'));
        self::assertTrue($guard->allows('https://example.com/resource'));
    }

    public function test_an_explicit_host_allowlist_can_permit_an_internal_service(): void
    {
        config()->set('laravel-waf.outbound.allowed_hosts', ['internal.example.test']);

        $guard = $this->app->make(OutboundUrlGuard::class);

        self::assertTrue($guard->allows('http://internal.example.test/status'));
        self::assertFalse($guard->allows('https://other.example.test/status'));
    }
}

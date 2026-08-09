<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\RequestContext;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;

final class RequestContextTest extends TestCase
{
    public function test_route_names_remain_raw_for_policy_and_bounded_for_labels(): void
    {
        $name = 'admin export/'.str_repeat('segment-', 12);
        $request = Request::create('/admin/export', 'post');
        $request->setRouteResolver(static fn (): object => new class($name) {
            public function __construct(private readonly string $name)
            {
            }

            public function getName(): string
            {
                return $this->name;
            }
        });

        self::assertSame($name, RequestContext::routeName($request));
        self::assertSame(
            substr(preg_replace('/[^A-Za-z0-9_.:-]/', '_', $name), 0, 64),
            RequestContext::routeLabel($request),
        );
        self::assertSame('POST', RequestContext::method($request));
    }

    public function test_missing_route_name_uses_the_stable_fallback(): void
    {
        $request = Request::create('/');

        self::assertSame('unnamed', RequestContext::routeName($request));
        self::assertSame('unnamed', RequestContext::routeLabel($request));
    }
}

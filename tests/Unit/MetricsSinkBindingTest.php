<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Support\NullMetricsSink;
use BillingServ\LaravelWaf\Support\UnixSocketMetricsSink;
use BillingServ\LaravelWaf\Tests\TestCase;

final class MetricsSinkBindingTest extends TestCase
{
    public function test_lwafd_owns_metrics_when_metrics_and_agent_are_enabled(): void
    {
        config()->set('laravel-waf.metrics.enabled', true);
        config()->set('laravel-waf.agent.enabled', true);
        app()->forgetInstance(MetricsSink::class);

        self::assertInstanceOf(UnixSocketMetricsSink::class, app(MetricsSink::class));
    }

    public function test_metrics_are_disabled_without_lwafd(): void
    {
        config()->set('laravel-waf.metrics.enabled', true);
        config()->set('laravel-waf.agent.enabled', false);
        app()->forgetInstance(MetricsSink::class);

        self::assertInstanceOf(NullMetricsSink::class, app(MetricsSink::class));
    }
}

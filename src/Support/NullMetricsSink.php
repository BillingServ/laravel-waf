<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\MetricsSink;

final class NullMetricsSink implements MetricsSink
{
    public function increment(string $name, array $labels = []): void
    {
        // Metrics must never become a request dependency.
    }

    public function observe(string $name, float $value, array $labels = []): void
    {
        // Metrics must never become a request dependency.
    }
}

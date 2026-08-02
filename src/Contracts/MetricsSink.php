<?php

namespace BillingServ\LaravelWaf\Contracts;

interface MetricsSink
{
    public function increment(string $name, array $labels = []): void;

    public function observe(string $name, float $value, array $labels = []): void;
}

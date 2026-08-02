<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\MetricsSink;
use Throwable;

final class MetricsRecorder
{
    public function __construct(private readonly MetricsSink $sink)
    {
    }

    public function decision(string $action, string $scope, string $route): void
    {
        $this->increment('decisions', [
            'action' => $action,
            'scope' => $scope,
            'route' => $this->routeLabel($route),
        ]);
    }

    public function agentBlock(string $outcome): void
    {
        $this->increment('agent_blocks', [
            'outcome' => $outcome,
        ]);
    }

    public function error(string $component): void
    {
        $this->increment('errors', [
            'component' => $component,
        ]);
    }

    public function evaluationDuration(float $seconds): void
    {
        try {
            $this->sink->observe('evaluation_duration_seconds', $seconds);
        } catch (Throwable) {
            // A metrics backend must never affect request handling.
        }
    }

    private function increment(string $name, array $labels): void
    {
        try {
            $this->sink->increment($name, $labels);
        } catch (Throwable) {
            // A metrics backend must never affect request handling.
        }
    }

    private function routeLabel(string $route): string
    {
        $route = preg_replace('/[^A-Za-z0-9_.:-]/', '_', $route) ?: 'unnamed';

        return substr($route, 0, 64);
    }
}

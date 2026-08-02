<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Security\Finding;
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

    public function finding(Finding $finding, string $action): void
    {
        $this->increment('findings', [
            'category' => $this->label($finding->category, 'unknown'),
            'rule' => $this->label($finding->rule, 'unknown'),
            'action' => $this->label($action, 'unknown'),
            'route' => $this->routeLabel($finding->route),
        ]);
    }

    public function notification(string $channel, string $outcome): void
    {
        $this->increment('notifications', [
            'channel' => $this->label($channel, 'unknown'),
            'outcome' => $this->label($outcome, 'unknown'),
        ]);
    }

    public function behavior(string $kind, string $outcome, string $route): void
    {
        $this->increment('behavior_events', [
            'kind' => $this->label($kind, 'unknown'),
            'outcome' => $this->label($outcome, 'unknown'),
            'route' => $this->routeLabel($route),
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
        return $this->label($route, 'unnamed', 64);
    }

    private function label(string $value, string $fallback, int $length = 32): string
    {
        $value = preg_replace('/[^A-Za-z0-9_.:-]/', '_', $value) ?: $fallback;

        return substr($value, 0, $length);
    }
}

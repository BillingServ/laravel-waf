<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\MetricsSink;
use Throwable;

final class PrometheusMetricsSink implements MetricsSink
{
    /** @var array<string, object> */
    private array $counters = [];

    /** @var array<string, object> */
    private array $histograms = [];

    public function __construct(
        private readonly object $registry,
        private readonly string $namespace = 'laravel_waf',
    ) {
    }

    public function increment(string $name, array $labels = []): void
    {
        try {
            $labels = $this->normalizeLabels($labels);
            $key = $name.'|'.implode(',', array_keys($labels));

            $counter = $this->counters[$key] ??= $this->registry->getOrRegisterCounter(
                $this->namespace,
                $name,
                $this->help($name),
                array_keys($labels),
            );

            $counter->inc(array_values($labels));
        } catch (Throwable) {
            // Observability must not take down the protected application.
        }
    }

    public function observe(string $name, float $value, array $labels = []): void
    {
        try {
            $labels = $this->normalizeLabels($labels);
            $key = $name.'|'.implode(',', array_keys($labels));

            $histogram = $this->histograms[$key] ??= $this->registry->getOrRegisterHistogram(
                $this->namespace,
                $name,
                $this->help($name),
                array_keys($labels),
            );

            $histogram->observe($value, array_values($labels));
        } catch (Throwable) {
            // Observability must not take down the protected application.
        }
    }

    /** @return array<string, string> */
    private function normalizeLabels(array $labels): array
    {
        ksort($labels);

        return array_map(static fn (mixed $value): string => (string) $value, $labels);
    }

    private function help(string $name): string
    {
        return match ($name) {
            'decisions' => 'Laravel WAF request decisions.',
            'findings' => 'Laravel WAF request inspection findings.',
            'agent_blocks' => 'Laravel WAF host-agent block decisions.',
            'notifications' => 'Laravel WAF security notification outcomes.',
            'behavior_events' => 'Laravel WAF response behavior events.',
            'errors' => 'Laravel WAF internal errors.',
            'evaluation_duration_seconds' => 'Laravel WAF middleware evaluation duration in seconds.',
            default => 'Laravel WAF metric.',
        };
    }
}

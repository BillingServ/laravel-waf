<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\MetricsRenderer;
use RuntimeException;

final class PrometheusRegistryRenderer implements MetricsRenderer
{
    public function available(): bool
    {
        return class_exists('Prometheus\\CollectorRegistry')
            && class_exists('Prometheus\\RenderTextFormat');
    }

    public function render(): string
    {
        if (!$this->available()) {
            throw new RuntimeException('Prometheus support is not installed.');
        }

        $registry = \Prometheus\CollectorRegistry::getDefault();
        $renderer = new \Prometheus\RenderTextFormat();

        return $renderer->render($registry->getMetricFamilySamples());
    }
}

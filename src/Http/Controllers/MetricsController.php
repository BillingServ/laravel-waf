<?php

namespace BillingServ\LaravelWaf\Http\Controllers;

use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class MetricsController
{
    public function __invoke(): Response
    {
        if (!class_exists('Prometheus\\CollectorRegistry') || !class_exists('Prometheus\\RenderTextFormat')) {
            return new Response('Prometheus support is not installed.', 503, [
                'Content-Type' => 'text/plain; charset=UTF-8',
            ]);
        }

        try {
            $registry = \Prometheus\CollectorRegistry::getDefault();
            $renderer = new \Prometheus\RenderTextFormat();
            $body = $renderer->render($registry->getMetricFamilySamples());

            return new Response($body, 200, [
                'Content-Type' => 'text/plain; version=0.0.4; charset=UTF-8',
            ]);
        } catch (Throwable) {
            return new Response('Prometheus metrics are temporarily unavailable.', 503, [
                'Content-Type' => 'text/plain; charset=UTF-8',
            ]);
        }
    }
}

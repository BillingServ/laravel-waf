<?php

namespace BillingServ\LaravelWaf\Http\Controllers;

use BillingServ\LaravelWaf\Contracts\AgentMetricsSource;
use BillingServ\LaravelWaf\Contracts\MetricsRenderer;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class MetricsController
{
    public function __construct(
        private readonly MetricsRenderer $renderer,
        private readonly AgentMetricsSource $agentMetrics,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if (!$this->allowed($request)) {
            return new Response('', 404, ['Cache-Control' => 'no-store']);
        }

        try {
            if (!$this->renderer->available()) {
                return new Response('Prometheus support is not installed.', 503, [
                    'Cache-Control' => 'no-store',
                    'Content-Type' => 'text/plain; charset=UTF-8',
                ]);
            }

            $body = rtrim($this->renderer->render(), "\r\n")."\n";
            if (config('laravel-waf.metrics.agent.enabled', false)) {
                $agent = $this->agent();
                $body .= $this->agentStatus($agent['up']);
                if ($agent['up'] && $agent['body'] !== '') {
                    $body .= rtrim($agent['body'], "\r\n")."\n";
                }
            }

            return new Response($body, 200, [
                'Cache-Control' => 'no-store',
                'Content-Type' => 'text/plain; version=0.0.4; charset=UTF-8',
            ]);
        } catch (Throwable) {
            return new Response('Prometheus metrics are temporarily unavailable.', 503, [
                'Cache-Control' => 'no-store',
                'Content-Type' => 'text/plain; charset=UTF-8',
            ]);
        }
    }

    private function allowed(Request $request): bool
    {
        $allowed = config('laravel-waf.metrics.allowed_ips', []);
        if (!is_array($allowed) || $allowed === []) {
            return false;
        }

        $ip = $request->ip();
        if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        foreach ($allowed as $range) {
            if (!is_string($range) || $range === '') {
                continue;
            }

            try {
                if (IpUtils::checkIp($ip, $range)) {
                    return true;
                }
            } catch (Throwable) {
                // Invalid entries fail closed and cannot expose the endpoint.
            }
        }

        return false;
    }

    /** @return array{up: bool, body: string} */
    private function agent(): array
    {
        try {
            $agent = $this->agentMetrics->collect();
            if (($agent['up'] ?? false) !== true || !is_string($agent['body'] ?? null)) {
                return ['up' => false, 'body' => ''];
            }

            return ['up' => true, 'body' => $agent['body']];
        } catch (Throwable) {
            return ['up' => false, 'body' => ''];
        }
    }

    private function agentStatus(bool $up): string
    {
        return "# HELP laravel_waf_agent_metrics_up Whether the local agent metrics source was collected.\n"
            ."# TYPE laravel_waf_agent_metrics_up gauge\n"
            .'laravel_waf_agent_metrics_up '.($up ? '1' : '0')."\n";
    }
}

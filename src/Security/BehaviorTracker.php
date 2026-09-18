<?php

namespace BillingServ\LaravelWaf\Security;

use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\RequestContext;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class BehaviorTracker
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly MetricsRecorder $metrics,
        private readonly ?Repository $cache = null,
    ) {
    }

    public function inspect(Request $request): ?Finding
    {
        if (!config('laravel-waf.behavior.enabled', true) || $this->skip($request)) {
            return null;
        }

        $ip = $request->ip() ?: 'unknown';
        $thresholds = array_filter($this->thresholds(), static fn (int $threshold): bool => $threshold > 0);
        if ($thresholds === []) {
            return null;
        }

        try {
            $keys = array_map(
                static fn (int|string $kind): string => RateLimitKey::behavior($ip, (string) $kind),
                array_keys($thresholds),
            );
            $attempts = $this->cache?->many($keys);

            foreach ($thresholds as $kind => $threshold) {
                $key = RateLimitKey::behavior($ip, $kind);
                if ($attempts !== null && ($attempts[$key] ?? 0) < $threshold) {
                    continue;
                }

                // Recheck reached thresholds through Laravel so timer expiry,
                // stale-counter resets and concurrent changes keep their semantics.
                if (!$this->limiter->tooManyAttempts($key, $threshold)) {
                    continue;
                }

                $alertKey = RateLimitKey::behaviorAlert($ip, $kind);
                $cooldown = max(1, (int) config('laravel-waf.behavior.alert_cooldown_seconds', 60));
                if (!$this->limiter->tooManyAttempts($alertKey, 1)) {
                    $this->limiter->hit($alertKey, $cooldown);
                    $this->metrics->behavior($kind, 'alert', RequestContext::routeLabel($request));
                }

                return $this->finding($request, $kind);
            }
        } catch (Throwable) {
            $this->metrics->error('behavior_tracker');

            return null;
        }

        return null;
    }

    public function record(Request $request, Response $response): void
    {
        if (!config('laravel-waf.behavior.enabled', true) || $this->skip($request)) {
            return;
        }

        $kinds = $this->kindsForStatus($response->getStatusCode());
        if ($kinds === []) {
            return;
        }

        $ip = $request->ip() ?: 'unknown';
        $window = $this->window();

        foreach ($kinds as $kind) {
            try {
                $this->limiter->hit(RateLimitKey::behavior($ip, $kind), $window);
                $this->metrics->behavior($kind, 'recorded', RequestContext::routeLabel($request));
            } catch (Throwable) {
                $this->metrics->error('behavior_tracker');

                return;
            }
        }
    }

    /** @return array<string, int> */
    private function thresholds(): array
    {
        $thresholds = config('laravel-waf.behavior.thresholds', []);

        return is_array($thresholds) ? array_map('intval', $thresholds) : [];
    }

    private function window(): int
    {
        return max(1, min(86400, (int) config('laravel-waf.behavior.window_seconds', 60)));
    }

    /** @return array<int, string> */
    private function kindsForStatus(int $status): array
    {
        $kinds = [];

        if ($status >= 400 && $status < 500) {
            $kinds[] = 'client_error';
        }

        $specific = (string) $status;
        if (array_key_exists($specific, $this->thresholds())) {
            $kinds[] = $specific;
        }

        return array_values(array_unique($kinds));
    }

    private function skip(Request $request): bool
    {
        $routes = config('laravel-waf.behavior.skip_routes', []);
        if (!is_array($routes)) {
            return false;
        }

        return in_array(RequestContext::routeLabel($request), array_values(array_filter($routes, 'is_string')), true);
    }

    private function finding(Request $request, string $kind): Finding
    {
        return new Finding(
            'behavior',
            'repeated_'.$kind,
            'high',
            'response',
            null,
            $request->ip() ?: 'unknown',
            RequestContext::routeLabel($request),
            RequestContext::method($request),
        );
    }
}

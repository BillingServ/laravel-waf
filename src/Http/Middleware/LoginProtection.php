<?php

namespace BillingServ\LaravelWaf\Http\Middleware;

use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class LoginProtection
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly MetricsRecorder $metrics,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('laravel-waf.enabled', true) || !config('laravel-waf.login.enabled', true)) {
            return $next($request);
        }

        $ip = $request->ip() ?: 'unknown';
        $identifier = $this->identifier($request);
        $maxAttempts = max(1, (int) config('laravel-waf.login.max_attempts', 5));

        try {
            $identityKey = RateLimitKey::login($ip, $identifier);
            $ipKey = RateLimitKey::login($ip);
            if ($this->limiter->tooManyAttempts($identityKey, $maxAttempts)
                || $this->limiter->tooManyAttempts($ipKey, $maxAttempts)) {
                $retryAfter = max(
                    1,
                    $this->limiter->availableIn($identityKey),
                    $this->limiter->availableIn($ipKey),
                );
                $this->metrics->decision('login_rate_limited', 'login', $this->routeName($request));

                return $this->blocked($request, $retryAfter);
            }
        } catch (Throwable) {
            $this->metrics->error('login_rate_limiter');

            if (config('laravel-waf.login.fail_mode', 'open') === 'closed') {
                return new Response('Login protection is temporarily unavailable.', 503, [
                    'Cache-Control' => 'no-store',
                    'Retry-After' => '5',
                ]);
            }
        }

        return $next($request);
    }

    private function blocked(Request $request, int $retryAfter): Response
    {
        $status = max(400, min(599, (int) config('laravel-waf.login.status', 429)));
        $headers = [
            'Cache-Control' => 'no-store',
            'Retry-After' => (string) $retryAfter,
            'X-Laravel-Waf-Login' => 'limited',
        ];

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Too many login attempts.'], $status, $headers);
        }

        return new Response('Too many login attempts. Please try again later.', $status, $headers);
    }

    private function identifier(Request $request): string
    {
        $field = config('laravel-waf.login.field', 'email');
        $value = is_string($field) && $field !== '' ? $request->input($field) : $request->input('email');

        return is_scalar($value) ? (string) $value : '';
    }

    private function routeName(Request $request): string
    {
        $route = $request->route();

        return is_object($route) && method_exists($route, 'getName')
            ? (string) ($route->getName() ?: 'unnamed')
            : 'unnamed';
    }
}

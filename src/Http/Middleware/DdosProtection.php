<?php

namespace BillingServ\LaravelWaf\Http\Middleware;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Support\AgentBlocker;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\InternalEndpoint;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\RequestContext;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class DdosProtection
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly AgentBlocker $agentBlocker,
        private readonly ChallengeResponder $challenge,
        private readonly ChallengeTokenManager $challengeTokens,
        private readonly MetricsRecorder $metrics,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $startedAt = hrtime(true);

        if (!config('laravel-waf.enabled', true) || !config('laravel-waf.ddos.enabled', true)) {
            return $this->finish($next($request), $startedAt);
        }

        $route = RequestContext::routeName($request);
        $challengeRoute = (string) config('laravel-waf.challenge.verify_route', 'laravel-waf.challenge.verify');
        $blockedRoute = (string) config('laravel-waf.challenge.blocked_route', 'laravel-waf.blocked');
        if (InternalEndpoint::matches($request)
            || $route === $challengeRoute
            || $route === $blockedRoute
            || in_array($route, config('laravel-waf.ddos.exempt_routes', []), true)) {
            return $this->finish($next($request), $startedAt);
        }

        if ($this->isTestTrigger($request)) {
            $request->attributes->set('laravel-waf.challenge_return_to', $this->testReturnTo($request));
            $this->metrics->decision('blocked_test', 'test', $route);

            return $this->finish(
                $this->challenge->respond($request, 60, 'test'),
                $startedAt,
            );
        }

        $ip = $request->ip() ?: 'unknown';
        $challengePassed = config('laravel-waf.challenge.enabled', false)
            && $this->challengeTokens->isPassed(
                $request->cookie((string) config('laravel-waf.challenge.cookie_name', 'laravel_waf_challenge')),
                $ip,
            );

        $agentGateRetryAfter = $this->agentGateRetryAfter($request, $challengePassed);
        if ($agentGateRetryAfter === 0) {
            $this->metrics->error('agent_gate_marker');

            return $this->finish($this->protectionUnavailable(), $startedAt);
        }
        if ($agentGateRetryAfter !== null) {
            $this->metrics->decision('challenge', 'agent_gate', $route);

            return $this->finish(
                $this->challenge->respond($request, $agentGateRetryAfter, 'agent_gate'),
                $startedAt,
            );
        }

        $adaptiveRetryAfter = $this->adaptiveRetryAfter($challengePassed);
        if ($adaptiveRetryAfter !== null) {
            $this->metrics->decision('challenge', 'adaptive', $route);

            return $this->finish(
                $this->challenge->respond($request, $adaptiveRetryAfter, 'adaptive'),
                $startedAt,
            );
        }

        $rules = $this->rules($route, $challengePassed);
        $violation = null;
        $remaining = PHP_INT_MAX;
        $limit = PHP_INT_MAX;

        try {
            foreach ($rules as $rule) {
                $key = RateLimitKey::for($rule['scope'], $ip, $rule['scope'] === 'route' ? $route : '');

                if ($this->limiter->tooManyAttempts($key, $rule['max_attempts'])) {
                    $violation = [
                        'scope' => $rule['scope'],
                        'retry_after' => max(1, $this->limiter->availableIn($key)),
                    ];
                    $remaining = 0;
                    $limit = $rule['max_attempts'];

                    break;
                }

                $remaining = min($remaining, $this->limiter->remaining($key, $rule['max_attempts']));
                $limit = min($limit, $rule['max_attempts']);
            }
        } catch (Throwable) {
            $this->metrics->error('rate_limiter');

            if (config('laravel-waf.ddos.fail_mode', 'open') === 'closed') {
                return $this->protectionUnavailable();
            }

            return $this->finish($next($request), $startedAt);
        }

        if ($violation !== null) {
            $mode = config('laravel-waf.ddos.mode', 'reject');
            $action = ! $challengePassed
                && $mode === 'challenge'
                && config('laravel-waf.challenge.enabled', false)
                ? 'challenge'
                : 'rate_limited';

            $this->metrics->decision($action, $violation['scope'], $route);
            if (!$challengePassed && config('laravel-waf.agent.auto_block_on_limit', false)) {
                $this->agentBlocker->block(
                    $ip,
                    (int) config('laravel-waf.agent.block_ttl_seconds', 900),
                    'rate_limit',
                    'rate_limit',
                );
            }

            if ($action === 'challenge') {
                return $this->finish(
                    $this->challenge->respond($request, $violation['retry_after'], $violation['scope']),
                    $startedAt,
                );
            }

            return $this->finish(
                $this->rateLimitedResponse($request, $violation['retry_after'], $limit),
                $startedAt,
            );
        }

        try {
            foreach ($rules as $rule) {
                $key = RateLimitKey::for($rule['scope'], $ip, $rule['scope'] === 'route' ? $route : '');
                $this->limiter->hit($key, $rule['decay_seconds']);
            }
        } catch (Throwable) {
            $this->metrics->error('rate_limiter');

            if (config('laravel-waf.ddos.fail_mode', 'open') === 'closed') {
                return $this->protectionUnavailable();
            }
        }

        $response = $next($request);

        if (config('laravel-waf.ddos.include_headers', true) && $limit !== PHP_INT_MAX) {
            $response->headers->set('X-RateLimit-Limit', (string) $limit);
            $response->headers->set('X-RateLimit-Remaining', (string) max(0, $remaining - 1));
        }

        return $this->finish($response, $startedAt);
    }

    /** @return array<int, array{scope: string, max_attempts: int, decay_seconds: int}> */
    private function rules(string $route, bool $challengePassed = false): array
    {
        $rules = [];
        $global = $challengePassed
            ? config('laravel-waf.challenge.passed.global', [])
            : config('laravel-waf.ddos.global', []);
        $routeRules = $challengePassed
            ? config('laravel-waf.challenge.passed.routes', [])
            : config('laravel-waf.ddos.routes', []);
        $routeRule = $routeRules[$route] ?? $routeRules['*'] ?? null;

        foreach ([['global', $global], ['route', $routeRule]] as [$scope, $rule]) {
            if (!is_array($rule)) {
                continue;
            }

            $maxAttempts = (int) ($rule['max_attempts'] ?? 0);
            $decaySeconds = (int) ($rule['decay_seconds'] ?? 0);

            if ($maxAttempts > 0 && $decaySeconds > 0) {
                $rules[] = [
                    'scope' => $scope,
                    'max_attempts' => $maxAttempts,
                    'decay_seconds' => $decaySeconds,
                ];
            }
        }

        return $rules;
    }

    private function adaptiveRetryAfter(bool $challengePassed): ?int
    {
        if (!config('laravel-waf.ddos.adaptive.enabled', false)
            || config('laravel-waf.ddos.mode', 'reject') !== 'challenge'
            || !config('laravel-waf.challenge.enabled', false)) {
            return null;
        }

        $challengeAfter = max(1, (int) config('laravel-waf.ddos.adaptive.challenge_after', 600));
        $windowSeconds = max(1, min(3600, (int) config('laravel-waf.ddos.adaptive.window_seconds', 60)));
        $key = RateLimitKey::trafficPressure();

        try {
            $this->limiter->hit($key, $windowSeconds);
            if ($challengePassed || $this->limiter->attempts($key) <= $challengeAfter) {
                return null;
            }

            return max(1, $this->limiter->availableIn($key));
        } catch (Throwable) {
            $this->metrics->error('adaptive_rate_limiter');

            return null;
        }
    }

    private function agentGateRetryAfter(Request $request, bool $challengePassed): ?int
    {
        if ($challengePassed || !config('laravel-waf.agent.gate.enabled', false)) {
            return null;
        }

        $header = config('laravel-waf.agent.gate.header', 'X-Laravel-Waf-Gate');
        if (!is_string($header) || preg_match('/^[A-Za-z0-9-]{1,64}$/', $header) !== 1) {
            return 0;
        }

        $provided = $request->headers->get($header);
        if ($provided === null || $provided === '') {
            return null;
        }

        $token = config('laravel-waf.agent.gate.token');
        if (!is_string($token)
            || strlen($token) < 32
            || strlen($token) > 256
            || config('laravel-waf.ddos.mode', 'reject') !== 'challenge'
            || !config('laravel-waf.challenge.enabled', false)
            || !hash_equals($token, $provided)) {
            return 0;
        }

        return max(1, min(3600, (int) config('laravel-waf.agent.gate.retry_after_seconds', 60)));
    }

    private function rateLimitedResponse(Request $request, int $retryAfter, int $limit): Response
    {
        $status = max(400, min(599, (int) config('laravel-waf.ddos.status', 429)));
        $headers = [
            'Cache-Control' => 'no-store',
            'Retry-After' => (string) max(1, $retryAfter),
        ];

        if (config('laravel-waf.ddos.include_headers', true)) {
            $headers['X-RateLimit-Limit'] = (string) $limit;
            $headers['X-RateLimit-Remaining'] = '0';
        }

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Too Many Requests'], $status, $headers);
        }

        return new Response('Too Many Requests', $status, $headers);
    }

    private function protectionUnavailable(): Response
    {
        return new Response('Request protection is temporarily unavailable.', 503, [
            'Cache-Control' => 'no-store',
            'Retry-After' => '5',
        ]);
    }

    private function finish(Response $response, int $startedAt): Response
    {
        $this->metrics->evaluationDuration((hrtime(true) - $startedAt) / 1_000_000_000);

        return $response;
    }

    private function isTestTrigger(Request $request): bool
    {
        if (!config('laravel-waf.testing.enabled', false)
            || !config('laravel-waf.challenge.enabled', false)
            || (app()->environment('production') && !config('laravel-waf.testing.allow_production', false))) {
            return false;
        }

        $parameter = config('laravel-waf.testing.parameter', 'test');
        if (!is_string($parameter) || preg_match('/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/', $parameter) !== 1) {
            return false;
        }

        if (!$request->query->has($parameter)) {
            return false;
        }

        $expected = config('laravel-waf.testing.value');
        if (!is_string($expected) || $expected === '') {
            return true;
        }

        $value = $request->query($parameter);

        return is_string($value) && hash_equals($expected, $value);
    }

    private function testReturnTo(Request $request): string
    {
        $uri = $request->getRequestUri();
        [$path, $query] = array_pad(explode('?', $uri, 2), 2, null);
        $parameter = (string) config('laravel-waf.testing.parameter', 'test');

        if (is_string($query) && $query !== '') {
            parse_str($query, $parameters);
            unset($parameters[$parameter]);
            $query = http_build_query($parameters);
        }

        return $path.($query !== '' ? '?'.$query : '');
    }
}

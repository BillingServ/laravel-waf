<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use Illuminate\Http\Request;

final class RoutePolicyRule implements InspectionRule
{
    public function inspect(Request $request): ?Finding
    {
        if (!config('laravel-waf.policies.enabled', false)) {
            return null;
        }

        $route = $request->route();
        $policy = $this->policy($request);
        if ($policy === null) {
            return null;
        }

        $methods = $policy['methods'] ?? $policy['allowed_methods'] ?? null;
        if (is_array($methods) && $methods !== [] && !$this->containsMethod($methods, $request->getMethod())) {
            return $this->finding($request, 'method_not_allowed');
        }

        $maxBodyBytes = (int) ($policy['max_body_bytes'] ?? 0);
        if ($maxBodyBytes > 0 && $this->bodyBytes($request) > $maxBodyBytes) {
            return $this->finding($request, 'body_too_large');
        }

        $contentTypes = $policy['content_types'] ?? $policy['allowed_content_types'] ?? null;
        if (is_array($contentTypes) && $contentTypes !== []
            && !$this->containsContentType($contentTypes, $request->headers->get('content-type', ''))) {
            return $this->finding($request, 'content_type_not_allowed');
        }

        $middleware = $this->routeMiddleware($route);
        if (!$this->hasRequiredMiddleware($middleware, $policy['required_middleware'] ?? [])) {
            return $this->finding($request, 'required_middleware_missing');
        }

        if ($this->hasForbiddenMiddleware($middleware, $policy['forbidden_middleware'] ?? [])) {
            return $this->finding($request, 'forbidden_middleware_present');
        }

        if (($policy['require_auth'] ?? false) === true
            && !$this->hasMiddleware($middleware, ['auth', 'authenticate'])) {
            return $this->finding($request, 'auth_middleware_missing');
        }

        return null;
    }

    /** @return array<string, mixed>|null */
    private function policy(Request $request): ?array
    {
        $routes = config('laravel-waf.policies.routes', []);
        if (!is_array($routes)) {
            return null;
        }

        $route = $request->route();
        $name = is_object($route) && method_exists($route, 'getName')
            ? (string) ($route->getName() ?: 'unnamed')
            : 'unnamed';
        $policy = $routes[$name] ?? $routes['*'] ?? null;

        return is_array($policy) ? $policy : null;
    }

    private function bodyBytes(Request $request): int
    {
        $contentLength = $request->headers->get('content-length');
        if (is_string($contentLength) && ctype_digit($contentLength)) {
            return (int) $contentLength;
        }

        try {
            return strlen($request->getContent(false));
        } catch (\Throwable) {
            return 0;
        }
    }

    /** @param array<int, mixed> $methods */
    private function containsMethod(array $methods, string $method): bool
    {
        $method = strtoupper($method);

        foreach ($methods as $allowed) {
            if (is_string($allowed) && strtoupper(trim($allowed)) === $method) {
                return true;
            }
        }

        return false;
    }

    /** @param array<int, mixed> $contentTypes */
    private function containsContentType(array $contentTypes, string $header): bool
    {
        $actual = strtolower(trim(explode(';', $header, 2)[0]));
        if ($actual === '') {
            return false;
        }

        foreach ($contentTypes as $allowed) {
            if (!is_string($allowed)) {
                continue;
            }

            $allowed = strtolower(trim(explode(';', $allowed, 2)[0]));
            if ($allowed === '*/*' || $allowed === $actual) {
                return true;
            }

            if (str_ends_with($allowed, '/*')
                && str_starts_with($actual, substr($allowed, 0, -1))) {
                return true;
            }
        }

        return false;
    }

    /** @return array<int, string> */
    private function routeMiddleware(mixed $route): array
    {
        if (!is_object($route) || !method_exists($route, 'middleware')) {
            return [];
        }

        $middleware = $route->middleware();

        return is_array($middleware) ? array_values(array_filter($middleware, 'is_string')) : [];
    }

    /** @param array<int, string> $middleware */
    private function hasRequiredMiddleware(array $middleware, mixed $required): bool
    {
        if (!is_array($required)) {
            return true;
        }

        foreach ($required as $name) {
            if (is_string($name) && !$this->hasMiddleware($middleware, [$name])) {
                return false;
            }
        }

        return true;
    }

    /** @param array<int, string> $middleware */
    private function hasForbiddenMiddleware(array $middleware, mixed $forbidden): bool
    {
        if (!is_array($forbidden)) {
            return false;
        }

        foreach ($forbidden as $name) {
            if (is_string($name) && $this->hasMiddleware($middleware, [$name])) {
                return true;
            }
        }

        return false;
    }

    /** @param array<int, string> $middleware @param array<int, string> $expected */
    private function hasMiddleware(array $middleware, array $expected): bool
    {
        foreach ($middleware as $actual) {
            $actual = strtolower(trim(explode(':', $actual, 2)[0]));

            foreach ($expected as $candidate) {
                $candidate = strtolower(trim(explode(':', $candidate, 2)[0]));
                if ($candidate === $actual
                    || ($candidate === 'auth' && str_ends_with($actual, '\\authenticate'))
                    || ($candidate === 'authenticate' && str_ends_with($actual, '\\authenticate'))
                    || ($candidate === 'guest' && str_ends_with($actual, '\\redirectifauthenticated'))
                    || ($candidate === 'signed' && str_ends_with($actual, '\\validatesignature'))) {
                    return true;
                }
            }
        }

        return false;
    }

    private function finding(Request $request, string $rule): Finding
    {
        $route = $request->route();
        $name = is_object($route) && method_exists($route, 'getName')
            ? (string) ($route->getName() ?: 'unnamed')
            : 'unnamed';

        return new Finding(
            'policy',
            $rule,
            'high',
            'route',
            null,
            $request->ip() ?: 'unknown',
            substr(preg_replace('/[^A-Za-z0-9_.:-]/', '_', $name) ?: 'unnamed', 0, 64),
            strtoupper(substr($request->getMethod(), 0, 16)),
        );
    }
}

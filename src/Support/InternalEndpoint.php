<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Http\Request;

final class InternalEndpoint
{
    public static function matches(Request $request): bool
    {
        $requestPath = self::normalize($request->path());
        if ($requestPath === null) {
            return false;
        }

        foreach ([
            config('laravel-waf.challenge.path', '_waf/challenge/verify'),
            config('laravel-waf.challenge.blocked_path', '_waf/blocked'),
            config('laravel-waf.metrics.route', '_waf/metrics'),
        ] as $configuredPath) {
            if (self::normalize($configuredPath) === $requestPath) {
                return true;
            }
        }

        return false;
    }

    private static function normalize(mixed $path): ?string
    {
        if (!is_string($path)) {
            return null;
        }

        $path = trim(trim($path), '/');

        return $path !== '' ? $path : null;
    }
}

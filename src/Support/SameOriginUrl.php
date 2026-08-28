<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Http\Request;
use Throwable;

final class SameOriginUrl
{
    /** @param array<string, mixed> $parameters */
    public static function route(
        Request $request,
        string $name,
        array $parameters = [],
        int $maxLength = 2048,
    ): ?string {
        try {
            // Laravel's relative route generation removes the request base URL
            // but can retain a path embedded in a forced URL root. Strip the
            // generator's complete root from its absolute route first, then
            // attach only the base URL received with this request.
            $path = self::routePath(
                route($name, $parameters),
                url('/'),
            );
        } catch (Throwable) {
            return null;
        }

        if (!is_string($path)
            || $path === ''
            || !str_starts_with($path, '/')
            || str_starts_with($path, '//')) {
            return null;
        }

        $baseUrl = rtrim($request->getBaseUrl(), '/');
        if ($baseUrl !== ''
            && (!str_starts_with($baseUrl, '/') || str_starts_with($baseUrl, '//'))) {
            return null;
        }

        $url = $baseUrl.$path;
        if (strlen($url) > $maxLength
            || str_contains($url, "\r")
            || str_contains($url, "\n")
            || str_contains($url, '\\')) {
            return null;
        }

        return $url;
    }

    private static function routePath(string $url, string $root): ?string
    {
        $parts = parse_url($url);
        $rootParts = parse_url($root);
        if (!is_array($parts) || !is_array($rootParts)) {
            return null;
        }

        $path = $parts['path'] ?? '/';
        $rootPath = rtrim((string) ($rootParts['path'] ?? ''), '/');
        if (!is_string($path) || !str_starts_with($path, '/')) {
            return null;
        }

        if ($rootPath !== '') {
            if ($path === $rootPath) {
                $path = '/';
            } elseif (str_starts_with($path, $rootPath.'/')) {
                $path = substr($path, strlen($rootPath));
            } else {
                return null;
            }
        }

        $query = isset($parts['query']) && $parts['query'] !== ''
            ? '?'.$parts['query']
            : '';

        return $path.$query;
    }
}

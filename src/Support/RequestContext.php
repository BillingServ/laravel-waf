<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class RequestContext
{
    public static function routeName(Request $request): string
    {
        $route = $request->route();

        if (!is_object($route) || !method_exists($route, 'getName')) {
            return 'unnamed';
        }

        $name = $route->getName();

        return is_string($name) && $name !== '' ? $name : 'unnamed';
    }

    public static function routeLabel(Request $request): string
    {
        $name = preg_replace('/[^A-Za-z0-9_.:-]/', '_', self::routeName($request)) ?: 'unnamed';

        return substr($name, 0, 64);
    }

    public static function method(Request $request): string
    {
        return strtoupper(substr($request->getMethod(), 0, 16));
    }

    /**
     * Check route middleware before the route pipeline runs. This is useful
     * to outer/global middleware that needs to coordinate with a route-level
     * control such as LoginProtection.
     *
     * @param array<int, string> $candidates
     */
    public static function hasMiddleware(Request $request, array $candidates, ?Router $router = null): bool
    {
        $route = $request->route();

        // Global middleware runs before Router::runRoute() installs the
        // request's route resolver. Match only for route metadata here; the
        // router will still dispatch the request normally afterward.
        if (!$route instanceof Route && $router !== null) {
            try {
                $route = $router->getRoutes()->match($request);
            } catch (Throwable) {
                return false;
            }
        }

        if (!$route instanceof Route) {
            return false;
        }

        try {
            $declared = $route->middleware();
            $excluded = (array) $route->getAction('excluded_middleware');

            // Do not gather controller middleware here. Legacy Laravel
            // controllers expose instance middleware through getMiddleware(),
            // and gathering it would construct the controller before the
            // global DDoS limiter can reject the request.
            $middleware = $router !== null
                ? $router->resolveMiddleware($declared, $excluded)
                : array_values(array_diff($declared, $excluded));
        } catch (Throwable) {
            return false;
        }

        if (!is_array($middleware)) {
            return false;
        }

        foreach ($middleware as $name) {
            if (!is_string($name)) {
                continue;
            }

            $class = explode(':', $name, 2)[0];
            if (in_array($name, $candidates, true) || in_array($class, $candidates, true)) {
                return true;
            }
        }

        return false;
    }
}

<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Http\Request;

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
}

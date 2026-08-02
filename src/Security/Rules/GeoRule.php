<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\GeoIpResolver;
use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use Illuminate\Http\Request;

final class GeoRule implements InspectionRule
{
    public function __construct(private readonly GeoIpResolver $resolver)
    {
    }

    public function inspect(Request $request): ?Finding
    {
        $allowed = $this->countries(config('laravel-waf.geo.allowed_countries', []));
        $denied = $this->countries(config('laravel-waf.geo.denied_countries', []));
        if ($allowed === [] && $denied === []) {
            return null;
        }

        $country = $this->resolver->country($request->ip() ?: '');
        if ($country === null) {
            if (config('laravel-waf.geo.unknown', 'allow') !== 'reject') {
                return null;
            }

            return $this->finding($request, 'country_unknown');
        }

        if (in_array($country, $denied, true) || ($allowed !== [] && !in_array($country, $allowed, true))) {
            return $this->finding($request, 'country_policy');
        }

        return null;
    }

    private function finding(Request $request, string $rule): Finding
    {
        $route = $request->route();
        $routeName = is_object($route) && method_exists($route, 'getName')
            ? (string) ($route->getName() ?: 'unnamed')
            : 'unnamed';

        return new Finding(
            'geo',
            $rule,
            'high',
            'geo',
            null,
            $request->ip() ?: 'unknown',
            substr(preg_replace('/[^A-Za-z0-9_.:-]/', '_', $routeName) ?: 'unnamed', 0, 64),
            strtoupper(substr($request->getMethod(), 0, 16)),
        );
    }

    /** @return array<int, string> */
    private function countries(mixed $countries): array
    {
        if (!is_array($countries)) {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn (mixed $country): string => is_string($country) ? strtoupper(trim($country)) : '',
            $countries,
        ), static fn (string $country): bool => preg_match('/^[A-Z]{2}$/', $country) === 1));
    }
}

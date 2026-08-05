<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\InputNormalizer;
use Illuminate\Http\Request;

final class SensitivePathRule implements InspectionRule
{
    public function inspect(Request $request): ?Finding
    {
        $path = InputNormalizer::normalize($request->getPathInfo());
        $segments = preg_split('~[\\\\/]+~', trim($path, "/\\")) ?: [];

        foreach ($segments as $index => $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                continue;
            }

            if (!str_starts_with($segment, '.')) {
                continue;
            }

            if ($index === 0 && $segment === '.well-known') {
                continue;
            }

            return new Finding(
                'lfi',
                'sensitive_dotfile',
                'high',
                'path',
                'path',
                $request->ip() ?: 'unknown',
                $this->route($request),
                strtoupper(substr($request->getMethod(), 0, 16)),
            );
        }

        return null;
    }

    private function route(Request $request): string
    {
        $route = $request->route();

        if (is_object($route) && method_exists($route, 'getName')) {
            return substr(preg_replace('/[^A-Za-z0-9_.:-]/', '_', (string) ($route->getName() ?: 'unnamed')) ?: 'unnamed', 0, 64);
        }

        return 'unnamed';
    }
}

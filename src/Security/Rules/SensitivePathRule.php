<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\InputNormalizer;
use BillingServ\LaravelWaf\Support\RequestContext;
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
                RequestContext::routeLabel($request),
                RequestContext::method($request),
            );
        }

        return null;
    }
}

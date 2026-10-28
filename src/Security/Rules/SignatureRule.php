<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Security\Signatures\SignatureLoader;
use BillingServ\LaravelWaf\Security\Signatures\SignatureRequest;
use BillingServ\LaravelWaf\Support\RequestContext;
use Illuminate\Http\Request;

final class SignatureRule implements InspectionRule
{
    public const EVALUATED = 'laravel-waf.signatures_evaluated';
    private const LOGGED = 'laravel-waf.signature_logs';

    public function __construct(
        private readonly SignatureLoader $loader,
        private readonly RequestInputCollector $inputs,
    ) {
    }

    public function inspect(Request $request): ?Finding
    {
        // SignatureProtection may already have evaluated this request as
        // global middleware; never report or ban the same request twice.
        if ($request->attributes->get(self::EVALUATED) === true) {
            return null;
        }
        // Before routing, route parameters are unavailable, so the collected
        // inputs must not be cached for the later full inspection.
        $view = new SignatureRequest($request, $this->inputs, $request->route() !== null);
        [$rule, $logged] = $this->loader->current()->match($view);
        $request->attributes->set(self::EVALUATED, true);
        $request->attributes->set(self::LOGGED, array_map(fn (array $match): Finding => $this->finding($request, $match), $logged));
        if ($rule === null) {
            return null;
        }

        return $this->finding($request, $rule);
    }

    /** @return array<int, Finding> */
    public static function takeLogged(Request $request): array
    {
        $logged = $request->attributes->get(self::LOGGED, []);
        $request->attributes->remove(self::LOGGED);

        return $logged;
    }

    private function finding(Request $request, array $rule): Finding
    {
        return new Finding(
            'signature',
            $rule['id'],
            'high',
            'request',
            null,
            $request->ip() ?: 'unknown',
            RequestContext::routeLabel($request),
            RequestContext::method($request),
            $rule['action'] === 'log' ? 'log' : 'reject',
            $rule['action'] === 'ban' ? $rule['ttl'] : 0,
        );
    }
}

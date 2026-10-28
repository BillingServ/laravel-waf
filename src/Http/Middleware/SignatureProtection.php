<?php

namespace BillingServ\LaravelWaf\Http\Middleware;

use BillingServ\LaravelWaf\Http\Responses\BlockedResponse;
use BillingServ\LaravelWaf\Security\Rules\SignatureRule;
use BillingServ\LaravelWaf\Security\Signatures\SignatureException;
use BillingServ\LaravelWaf\Support\InternalEndpoint;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Evaluates signatures as global middleware. Route-group middleware such as
 * WafProtection never runs for unmatched routes, so scanner probes that end
 * in a 404 or 405 are only visible to Laravel from here. The check is cheap
 * and marks the request so WafProtection does not repeat it.
 */
final class SignatureProtection
{
    public function __construct(
        private readonly SignatureRule $rule,
        private readonly RequestInspection $inspection,
        private readonly MetricsRecorder $metrics,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('laravel-waf.enabled', true)
            || !config('laravel-waf.rules.enabled', true)
            || !config('laravel-waf.signatures.enabled', true)
            || InternalEndpoint::matches($request)) {
            return $next($request);
        }

        try {
            $finding = $this->rule->inspect($request);
        } catch (Throwable $exception) {
            $this->metrics->error('signatures');

            return $exception instanceof SignatureException
                ? $this->inspection->unavailable($request)
                : $next($request);
        }

        foreach (SignatureRule::takeLogged($request) as $logged) {
            $this->inspection->report($logged);
        }

        if ($finding === null || $this->inspection->report($finding) === 'log') {
            return $next($request);
        }

        $this->metrics->decision('blocked', 'signature', $finding->route);

        return BlockedResponse::make($request, max(400, min(599, (int) config('laravel-waf.rules.status', 403))));
    }
}

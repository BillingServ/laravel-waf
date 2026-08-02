<?php

namespace BillingServ\LaravelWaf\Http\Middleware;

use BillingServ\LaravelWaf\Support\SecurityHeaders;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class WafProtection
{
    public function __construct(
        private readonly RequestInspection $inspection,
        private readonly DdosProtection $ddos,
        private readonly SecurityHeaders $headers,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $response = $this->inspection->handle(
            $request,
            fn (Request $request): Response => $this->ddos->handle($request, $next),
        );

        $this->headers->apply($request, $response);

        return $response;
    }
}

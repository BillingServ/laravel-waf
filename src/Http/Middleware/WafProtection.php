<?php

namespace BillingServ\LaravelWaf\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class WafProtection
{
    public function __construct(
        private readonly RequestInspection $inspection,
        private readonly DdosProtection $ddos,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        return $this->inspection->handle(
            $request,
            fn (Request $request): Response => $this->ddos->handle($request, $next),
        );
    }
}

<?php

namespace BillingServ\LaravelWaf\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface ChallengeResponder
{
    public function respond(Request $request, int $retryAfter, string $scope): Response;
}

<?php

namespace BillingServ\LaravelWaf\Contracts;

interface ChallengeVerifier
{
    public function verify(mixed $payload): bool;
}

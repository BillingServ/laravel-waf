<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;

final class NullChallengeVerifier implements ChallengeVerifier
{
    public function verify(mixed $payload): bool
    {
        return false;
    }
}

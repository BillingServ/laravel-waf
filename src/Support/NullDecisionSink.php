<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\DecisionSink;

final class NullDecisionSink implements DecisionSink
{
    public function block(string $ip, int $ttlSeconds, string $reason): void
    {
        // Intentionally empty. Host-level enforcement is opt-in.
    }
}

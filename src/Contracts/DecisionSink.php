<?php

namespace BillingServ\LaravelWaf\Contracts;

interface DecisionSink
{
    public function block(string $ip, int $ttlSeconds, string $reason): void;
}

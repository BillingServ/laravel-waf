<?php

namespace BillingServ\LaravelWaf\Contracts;

interface AgentMetricsSource
{
    /** @return array{up: bool, body: string} */
    public function collect(): array;
}

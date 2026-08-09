<?php

namespace BillingServ\LaravelWaf\Contracts;

interface MetricsRenderer
{
    public function available(): bool;

    public function render(): string;
}

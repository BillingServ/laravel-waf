<?php

namespace BillingServ\LaravelWaf\Contracts;

interface GeoIpResolver
{
    public function country(string $ip): ?string;
}

<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\GeoIpResolver;

final class NullGeoIpResolver implements GeoIpResolver
{
    public function country(string $ip): ?string
    {
        return null;
    }
}

<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\GeoIpResolver;

final class MaxMindGeoIpResolver implements GeoIpResolver
{
    public function __construct(private readonly object $reader)
    {
    }

    public function country(string $ip): ?string
    {
        try {
            $record = $this->reader->country($ip);
            $country = $record->country->isoCode ?? null;

            if (!is_string($country) || preg_match('/^[A-Za-z]{2}$/', $country) !== 1) {
                return null;
            }

            return strtoupper($country);
        } catch (\Throwable) {
            return null;
        }
    }
}

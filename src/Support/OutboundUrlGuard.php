<?php

namespace BillingServ\LaravelWaf\Support;

use InvalidArgumentException;
use Throwable;

final class OutboundUrlGuard
{
    public function allows(string $url): bool
    {
        try {
            $this->assertAllowed($url);
        } catch (Throwable) {
            return false;
        }

        return true;
    }

    public function assertAllowed(string $url): void
    {
        $parts = UrlSafety::parse($url);
        if ($parts === null) {
            throw new InvalidArgumentException('The outbound URL is invalid.');
        }

        $allowedSchemes = config('laravel-waf.outbound.allowed_schemes', ['http', 'https']);
        if (!is_array($allowedSchemes)
            || !in_array($parts['scheme'], array_map('strtolower', array_filter($allowedSchemes, 'is_string')), true)) {
            throw new InvalidArgumentException('The outbound URL scheme is not allowed.');
        }

        $allowedHosts = config('laravel-waf.outbound.allowed_hosts', []);
        $hostIsAllowed = UrlSafety::isAllowedHost($parts['host'], $allowedHosts);
        if (! $hostIsAllowed
            && !(bool) config('laravel-waf.outbound.allow_private_ips', false)
            && UrlSafety::isPrivateHost($parts['host'])) {
            throw new InvalidArgumentException('The outbound URL points to a private or reserved host.');
        }

        if (is_array($allowedHosts) && $allowedHosts !== [] && !$hostIsAllowed) {
            throw new InvalidArgumentException('The outbound URL host is not allowed.');
        }

        if ((bool) config('laravel-waf.outbound.resolve_dns', false) && !$this->resolvesToPublicAddress($parts['host'])) {
            throw new InvalidArgumentException('The outbound URL host does not resolve to a public address.');
        }
    }

    private function resolvesToPublicAddress(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return !UrlSafety::isPrivateHost($host);
        }

        $records = dns_get_record($host, DNS_A | DNS_AAAA);
        if (!is_array($records) || $records === []) {
            return false;
        }

        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($address) && UrlSafety::isPrivateHost($address)) {
                return false;
            }
        }

        return true;
    }
}

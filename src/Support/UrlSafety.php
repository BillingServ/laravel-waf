<?php

namespace BillingServ\LaravelWaf\Support;

final class UrlSafety
{
    /** @return array{scheme: string, host: string, port: int|null}|null */
    public static function parse(string $value, bool $assumeHttp = false): ?array
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        if (str_starts_with($value, '//')) {
            $value = 'http:'.$value;
        } elseif ($assumeHttp && !preg_match('~^[A-Za-z][A-Za-z0-9+.-]*://~', $value)) {
            $value = 'http://'.$value;
        }

        try {
            $parts = parse_url($value);
        } catch (\Throwable) {
            return null;
        }
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower(trim(rtrim((string) $parts['host'], '.'), '[]'));
        if ($scheme === '' || $host === '') {
            return null;
        }

        return [
            'scheme' => $scheme,
            'host' => $host,
            'port' => isset($parts['port']) ? (int) $parts['port'] : null,
        ];
    }

    public static function isAllowedHost(string $host, mixed $allowedHosts): bool
    {
        if (!is_array($allowedHosts)) {
            return false;
        }

        $host = strtolower(rtrim($host, '.'));
        foreach ($allowedHosts as $allowed) {
            if (!is_string($allowed)) {
                continue;
            }

            $allowed = strtolower(trim($allowed));
            if ($allowed === '') {
                continue;
            }

            $allowed = ltrim($allowed, '*.');
            if ($host === $allowed || str_ends_with($host, '.'.$allowed)) {
                return true;
            }
        }

        return false;
    }

    public static function isPrivateHost(string $host): bool
    {
        $host = strtolower(rtrim($host, '.'));
        if (in_array($host, [
            'localhost',
            'localhost.localdomain',
            'ip6-localhost',
            'metadata',
            'metadata.google.internal',
            'instance-data',
        ], true)) {
            return true;
        }

        $ip = filter_var($host, FILTER_VALIDATE_IP);
        if ($ip !== false) {
            return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
        }

        if (ctype_digit($host) && (int) $host <= 4294967295) {
            return self::isPrivateHost(long2ip((int) $host));
        }

        if (preg_match('/^0x[0-9a-f]+$/i', $host) === 1) {
            $number = hexdec(substr($host, 2));
            if ($number <= 4294967295) {
                return self::isPrivateHost(long2ip((int) $number));
            }
        }

        return false;
    }
}

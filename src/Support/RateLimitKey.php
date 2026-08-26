<?php

namespace BillingServ\LaravelWaf\Support;

final class RateLimitKey
{
    public static function for(string $scope, string $ip, string $route = ''): string
    {
        $identity = hash('sha256', self::identity($ip).'|'.$route);

        return 'laravel-waf:rate:'.$scope.':'.$identity;
    }

    public static function agentBlock(string $ip): string
    {
        return 'laravel-waf:agent-block:'.hash('sha256', $ip);
    }

    public static function challenge(string $ip): string
    {
        return 'laravel-waf:challenge:'.hash('sha256', $ip);
    }

    public static function challengeToken(string $token): string
    {
        return 'laravel-waf:challenge-token:'.hash('sha256', $token);
    }

    public static function challengePayload(string $payload): string
    {
        return 'laravel-waf:challenge-payload:'.hash('sha256', $payload);
    }

    public static function trafficPressure(): string
    {
        return 'laravel-waf:traffic-pressure';
    }

    public static function login(string $ip, string $identifier = ''): string
    {
        return 'laravel-waf:login:'.hash('sha256', $ip.'|'.strtolower(trim($identifier)));
    }

    public static function securityBlock(string $ip, string $category): string
    {
        return 'laravel-waf:security-block:'.hash('sha256', $ip.'|'.$category);
    }

    public static function notification(string $fingerprint): string
    {
        return 'laravel-waf:notification:'.hash('sha256', $fingerprint);
    }

    public static function behavior(string $ip, string $kind): string
    {
        return 'laravel-waf:behavior:'.hash('sha256', self::identity($ip).'|'.$kind);
    }

    public static function behaviorAlert(string $ip, string $kind): string
    {
        return 'laravel-waf:behavior-alert:'.hash('sha256', self::identity($ip).'|'.$kind);
    }

    /**
     * Flood counters group IPv6 clients by /64 prefix so rotating individual
     * addresses within one allocated block cannot bypass the limits. Block,
     * challenge, and login keys keep the exact address.
     */
    private static function identity(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return $ip;
        }

        $binary = @inet_pton($ip);
        if ($binary === false || strlen($binary) !== 16) {
            return $ip;
        }

        // IPv4-mapped clients (::ffff:a.b.c.d) must fall back to their exact
        // IPv4 address; grouping them by /64 would share one bucket between
        // every dual-stack client.
        if (str_starts_with($binary, "\0\0\0\0\0\0\0\0\0\0\xff\xff")) {
            return long2ip((int) unpack('N', substr($binary, 12))[1]);
        }

        return inet_ntop(substr($binary, 0, 8).str_repeat("\0", 8));
    }
}

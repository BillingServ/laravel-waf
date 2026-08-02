<?php

namespace BillingServ\LaravelWaf\Support;

final class RateLimitKey
{
    public static function for(string $scope, string $ip, string $route = ''): string
    {
        $identity = hash('sha256', $ip.'|'.$route);

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
}

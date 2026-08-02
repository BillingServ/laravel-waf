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
}

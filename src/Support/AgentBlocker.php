<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\DecisionSink;
use Illuminate\Cache\RateLimiter;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Throwable;

final class AgentBlocker
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly DecisionSink $decisions,
        private readonly MetricsRecorder $metrics,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function block(string $ip, int $ttlSeconds, string $reason, string $scope): void
    {
        if (!config('laravel-waf.agent.enabled', false)
            || filter_var($ip, FILTER_VALIDATE_IP) === false
            || IpUtils::checkIp($ip, ['127.0.0.0/8', '::1'])) {
            return;
        }

        $key = RateLimitKey::securityBlock($ip, $scope);
        $cooldown = max(1, (int) config('laravel-waf.agent.block_cooldown_seconds', 60));

        try {
            if ($this->limiter->tooManyAttempts($key, 1)) {
                return;
            }

            $this->limiter->hit($key, $cooldown);
            $this->decisions->block($ip, max(1, $ttlSeconds), $reason);
        } catch (Throwable $exception) {
            $this->metrics->error('agent_decision');
            $this->warning($reason, $scope, $exception);
        }
    }

    private function warning(string $reason, string $scope, Throwable $exception): void
    {
        try {
            $this->logger->warning('Laravel WAF agent block dispatch failed.', [
                'exception' => $exception::class,
                'reason' => $reason,
                'scope' => $scope,
            ]);
        } catch (Throwable) {
            $this->metrics->error('security_logging');
        }
    }
}

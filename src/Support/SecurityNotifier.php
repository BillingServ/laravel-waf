<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Security\Finding;
use Illuminate\Cache\Repository;
use Psr\Log\LoggerInterface;
use Throwable;

final class SecurityNotifier
{
    public function __construct(
        private readonly Repository $cache,
        private readonly NotificationSink $sink,
        private readonly MetricsRecorder $metrics,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function notify(Finding $finding): void
    {
        if (!config('laravel-waf.notifications.enabled', false)) {
            return;
        }

        $cooldown = max(1, min(86400, (int) config('laravel-waf.notifications.cooldown_seconds', 300)));

        try {
            if (!$this->cache->add(RateLimitKey::notification($finding->fingerprint()), true, $cooldown)) {
                $this->metrics->notification('all', 'deduplicated');

                return;
            }
        } catch (Throwable $exception) {
            $this->metrics->error('notification_deduplication');
            $this->logger->warning('Laravel WAF notification deduplication failed.', [
                'exception' => $exception::class,
            ]);

            return;
        }

        try {
            $this->sink->notify($finding);
            $this->metrics->notification('configured', 'sent');
        } catch (Throwable $exception) {
            $this->metrics->notification('configured', 'failed');
            $this->warning('Laravel WAF notification delivery failed.', [
                'exception' => $exception::class,
                'category' => $finding->category,
                'rule' => $finding->rule,
            ]);
        }
    }

    /** @param array<string, string> $context */
    private function warning(string $message, array $context): void
    {
        try {
            $this->logger->warning($message, $context);
        } catch (Throwable) {
            $this->metrics->error('security_logging');
        }
    }
}

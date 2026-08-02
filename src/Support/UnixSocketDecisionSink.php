<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\DecisionSink;
use Throwable;

final class UnixSocketDecisionSink implements DecisionSink
{
    public function __construct(
        private readonly string $socket,
        private readonly ?string $secret,
        private readonly int $timeoutMilliseconds,
        private readonly MetricsRecorder $metrics,
    ) {
    }

    public function block(string $ip, int $ttlSeconds, string $reason): void
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->metrics->agentBlock('invalid_ip');

            return;
        }

        $ttlSeconds = max(1, min(86400, $ttlSeconds));
        $reason = $this->reason($reason);
        $payload = [
            'version' => 1,
            'action' => 'block_ip',
            'ip' => $ip,
            'ttl_seconds' => $ttlSeconds,
            'reason' => $reason,
        ];

        if ($this->secret !== null && $this->secret !== '') {
            $payload['signature'] = hash_hmac('sha256', $this->canonical($payload), $this->secret);
        }

        try {
            $timeout = max(0.001, $this->timeoutMilliseconds / 1000);
            $client = @stream_socket_client(
                'unix://'.$this->socket,
                $errorNumber,
                $errorMessage,
                $timeout,
                STREAM_CLIENT_CONNECT,
            );

            if ($client === false) {
                $this->metrics->agentBlock('connect_error');

                return;
            }

            stream_set_timeout($client, intdiv($this->timeoutMilliseconds, 1000), ($this->timeoutMilliseconds % 1000) * 1000);
            fwrite($client, json_encode($payload, JSON_THROW_ON_ERROR)."\n");
            $response = fgets($client);
            fclose($client);

            $decoded = is_string($response) ? json_decode($response, true, 512, JSON_THROW_ON_ERROR) : null;
            $this->metrics->agentBlock(is_array($decoded) && ($decoded['ok'] ?? false) === true ? 'accepted' : 'rejected');
        } catch (Throwable) {
            if (isset($client) && is_resource($client)) {
                fclose($client);
            }

            $this->metrics->agentBlock('error');
        }
    }

    /** @param array<string, int|string> $payload */
    private function canonical(array $payload): string
    {
        $reason = rtrim(strtr(base64_encode((string) $payload['reason']), '+/', '-_'), '=');

        return implode("\n", [
            (string) $payload['version'],
            (string) $payload['action'],
            (string) $payload['ip'],
            (string) $payload['ttl_seconds'],
            $reason,
        ]);
    }

    private function reason(string $reason): string
    {
        $reason = preg_replace('/[^A-Za-z0-9_.:-]/', '_', $reason) ?: 'rate_limit';

        return substr($reason, 0, 64);
    }
}

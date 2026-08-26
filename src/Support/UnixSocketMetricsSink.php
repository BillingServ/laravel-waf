<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\MetricsSink;
use Throwable;

final class UnixSocketMetricsSink implements MetricsSink
{
    private const MAX_EVENT_BYTES = 8192;

    private const MAX_OBSERVATION_SECONDS = 3600;

    public function __construct(
        private readonly string $socket,
        private readonly ?string $secret,
        private readonly int $timeoutMilliseconds = 1,
    ) {
    }

    public function increment(string $name, array $labels = []): void
    {
        $this->send('increment', $name, $labels, 1);
    }

    public function observe(string $name, float $value, array $labels = []): void
    {
        $seconds = max(0.0, min(self::MAX_OBSERVATION_SECONDS, $value));
        $this->send('observe', $name, $labels, (int) round($seconds * 1_000_000_000));
    }

    /** @param array<string, mixed> $labels */
    private function send(string $operation, string $name, array $labels, int $value): void
    {
        try {
            if (!$this->validSocket() || preg_match('/^[a-z][a-z0-9_]{0,63}$/D', $name) !== 1) {
                return;
            }

            $labels = $this->labels($labels);
            if ($labels === null) {
                return;
            }

            $payload = [
                'version' => 1,
                'action' => 'record_metric',
                'operation' => $operation,
                'name' => $name,
                'labels' => $labels === [] ? new \stdClass() : $labels,
                'value' => $value,
            ];
            if ($this->secret !== null && $this->secret !== '') {
                $payload['signature'] = hash_hmac('sha256', $this->canonical($payload, $labels), $this->secret);
            }

            $encoded = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)."\n";
            if (strlen($encoded) > self::MAX_EVENT_BYTES) {
                return;
            }

            $timeout = max(0.001, min(0.025, $this->timeoutMilliseconds / 1000));
            // One event per connection: the Go agent closes the socket after
            // a single line, so persistent pooling would reuse dead streams.
            $client = @stream_socket_client(
                'unix://'.$this->socket,
                $errorNumber,
                $errorMessage,
                $timeout,
                STREAM_CLIENT_CONNECT,
            );
            if ($client === false) {
                return;
            }

            stream_set_timeout($client, 0, max(1000, $this->timeoutMilliseconds * 1000));
            @fwrite($client, $encoded);
            fclose($client);
        } catch (Throwable) {
            if (isset($client) && is_resource($client)) {
                fclose($client);
            }
        }
    }

    /**
     * @param array<string, int|string|\stdClass> $payload
     * @param array<string, string> $labels
     */
    private function canonical(array $payload, array $labels): string
    {
        $lines = [
            (string) $payload['version'],
            (string) $payload['action'],
            (string) $payload['operation'],
            (string) $payload['name'],
            (string) $payload['value'],
        ];

        foreach ($labels as $name => $value) {
            $encoded = rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
            $lines[] = $name.'='.$encoded;
        }

        return implode("\n", $lines);
    }

    /** @param array<string, mixed> $labels
     *  @return array<string, string>|null
     */
    private function labels(array $labels): ?array
    {
        if (count($labels) > 8) {
            return null;
        }

        $normalized = [];
        foreach ($labels as $name => $value) {
            $name = (string) $name;
            $value = (string) $value;
            if (preg_match('/^[a-z][a-z0-9_]{0,31}$/D', $name) !== 1
                || preg_match('/^[A-Za-z0-9_.:-]{1,64}$/D', $value) !== 1) {
                return null;
            }
            $normalized[$name] = $value;
        }
        ksort($normalized);

        return $normalized;
    }

    private function validSocket(): bool
    {
        return str_starts_with($this->socket, '/')
            && strlen($this->socket) <= 1024
            && !str_contains($this->socket, "\0")
            && !str_contains($this->socket, "\n")
            && !str_contains($this->socket, "\r");
    }
}

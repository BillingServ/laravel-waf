<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\AgentMetricsSource;
use Throwable;

final class LoopbackAgentMetricsSource implements AgentMetricsSource
{
    public function __construct(
        private readonly string $endpoint,
        private readonly int $timeoutMilliseconds = 100,
        private readonly int $maxResponseBytes = 1048576,
    ) {
    }

    public function collect(): array
    {
        $target = $this->target();
        if ($target === null) {
            return $this->unavailable();
        }

        $client = null;
        try {
            $timeoutMilliseconds = max(10, min(2000, $this->timeoutMilliseconds));
            $timeout = $timeoutMilliseconds / 1000;
            $client = @stream_socket_client(
                $target['socket'],
                $errorNumber,
                $errorMessage,
                $timeout,
                STREAM_CLIENT_CONNECT,
            );
            if ($client === false) {
                return $this->unavailable();
            }

            stream_set_timeout(
                $client,
                intdiv($timeoutMilliseconds, 1000),
                ($timeoutMilliseconds % 1000) * 1000,
            );

            $request = "GET {$target['path']} HTTP/1.0\r\n"
                ."Host: {$target['host']}\r\n"
                ."Accept: text/plain\r\n"
                ."Connection: close\r\n\r\n";
            if (fwrite($client, $request) !== strlen($request)) {
                return $this->unavailable();
            }

            $maxBytes = max(1024, min(4194304, $this->maxResponseBytes));
            $response = stream_get_contents($client, $maxBytes + 8193);
            $metadata = stream_get_meta_data($client);
            if (!is_string($response) || ($metadata['timed_out'] ?? false) === true) {
                return $this->unavailable();
            }

            return $this->decode($response, $maxBytes);
        } catch (Throwable) {
            return $this->unavailable();
        } finally {
            if (is_resource($client)) {
                fclose($client);
            }
        }
    }

    /** @return array{socket: string, host: string, path: string}|null */
    private function target(): ?array
    {
        if ($this->endpoint === '' || strlen($this->endpoint) > 2048) {
            return null;
        }

        try {
            $parts = parse_url($this->endpoint);
        } catch (Throwable) {
            return null;
        }
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'http'
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            return null;
        }

        $host = strtolower(trim((string) ($parts['host'] ?? ''), '[]'));
        if (!in_array($host, ['127.0.0.1', '::1'], true)) {
            return null;
        }

        $port = (int) ($parts['port'] ?? 80);
        $path = (string) ($parts['path'] ?? '/metrics');
        if ($port < 1 || $port > 65535
            || !str_starts_with($path, '/')
            || strlen($path) > 1024
            || preg_match('/[\x00-\x20\x7f]/', $path) === 1) {
            return null;
        }

        $address = $host === '::1' ? '[::1]' : $host;

        return [
            'socket' => "tcp://{$address}:{$port}",
            'host' => "{$address}:{$port}",
            'path' => $path,
        ];
    }

    /** @return array{up: bool, body: string} */
    private function decode(string $response, int $maxBytes): array
    {
        $separator = strpos($response, "\r\n\r\n");
        $separatorLength = 4;
        if ($separator === false) {
            $separator = strpos($response, "\n\n");
            $separatorLength = 2;
        }
        if ($separator === false || $separator > 8192) {
            return $this->unavailable();
        }

        $headers = substr($response, 0, $separator);
        $body = substr($response, $separator + $separatorLength);
        if (preg_match('/^HTTP\/1\.[01] 200(?:\s|$)/', $headers) !== 1
            || stripos($headers, "\nTransfer-Encoding: chunked") !== false
            || strlen($body) > $maxBytes) {
            return $this->unavailable();
        }

        return [
            'up' => true,
            'body' => $body === '' ? '' : rtrim($body, "\r\n")."\n",
        ];
    }

    /** @return array{up: false, body: string} */
    private function unavailable(): array
    {
        return ['up' => false, 'body' => ''];
    }
}

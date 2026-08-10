<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\UnixSocketMetricsSink;
use PHPUnit\Framework\TestCase;

final class UnixSocketMetricsSinkTest extends TestCase
{
    public function test_it_sends_a_signed_bounded_metric_event(): void
    {
        $socket = sys_get_temp_dir().'/lwafd-metrics-'.bin2hex(random_bytes(8)).'.sock';
        $server = @stream_socket_server('unix://'.$socket, $errorNumber, $errorMessage);
        if ($server === false) {
            self::markTestSkipped('A Unix socket test listener could not be created.');
        }

        try {
            (new UnixSocketMetricsSink($socket, 'test-secret', 10))->increment('decisions', [
                'scope' => 'rule',
                'route' => 'admin.login',
                'action' => 'blocked',
            ]);

            $connection = stream_socket_accept($server, 1);
            self::assertIsResource($connection);
            $line = fgets($connection);
            fclose($connection);

            self::assertIsString($line);
            $payload = json_decode($line, true, 8, JSON_THROW_ON_ERROR);
            self::assertSame(1, $payload['version']);
            self::assertSame('record_metric', $payload['action']);
            self::assertSame('increment', $payload['operation']);
            self::assertSame('decisions', $payload['name']);
            self::assertSame([
                'action' => 'blocked',
                'route' => 'admin.login',
                'scope' => 'rule',
            ], $payload['labels']);
            self::assertSame(1, $payload['value']);
            self::assertSame(
                'd3ec25e70de177734ef8e70487d9d528a703661469e8e6f0ad2e4b6444f351bd',
                $payload['signature'],
            );
        } finally {
            fclose($server);
            @unlink($socket);
        }
    }

    public function test_transport_failures_never_escape_into_request_handling(): void
    {
        (new UnixSocketMetricsSink('/missing/lwafd/metrics.sock', 'test-secret'))->increment('errors', [
            'component' => 'rate_limiter',
        ]);

        self::assertTrue(true);
    }
}

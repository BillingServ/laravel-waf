<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\LoopbackAgentMetricsSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LoopbackAgentMetricsSourceTest extends TestCase
{
    public function test_agent_source_collects_a_bounded_loopback_http_response(): void
    {
        if (!function_exists('pcntl_fork') || !function_exists('pcntl_waitpid')) {
            self::markTestSkipped('The pcntl extension is required for the loopback transport test.');
        }

        $server = @stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $errorMessage);
        if ($server === false) {
            self::markTestSkipped('A loopback test listener could not be created.');
        }
        $address = stream_socket_get_name($server, false);
        self::assertIsString($address);
        $port = (int) substr((string) strrchr($address, ':'), 1);

        $pid = pcntl_fork();
        if ($pid === -1) {
            fclose($server);
            self::markTestSkipped('The loopback test process could not be started.');
        }
        if ($pid === 0) {
            $connection = stream_socket_accept($server, 2);
            if (!is_resource($connection)) {
                exit(1);
            }

            $request = '';
            while (!str_contains($request, "\r\n\r\n") && !feof($connection)) {
                $request .= (string) fread($connection, 1024);
            }
            $body = "laravel_waf_agent_test_total 4\n";
            fwrite($connection, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ".strlen($body)."\r\n\r\n".$body);
            fclose($connection);
            fclose($server);
            exit(0);
        }

        fclose($server);
        $result = (new LoopbackAgentMetricsSource("http://127.0.0.1:{$port}/metrics", 500))->collect();
        pcntl_waitpid($pid, $status);

        self::assertSame(0, pcntl_wexitstatus($status));
        self::assertSame(['up' => true, 'body' => "laravel_waf_agent_test_total 4\n"], $result);
    }

    #[DataProvider('unsafeEndpoints')]
    public function test_agent_source_rejects_non_loopback_or_ambiguous_endpoints(string $endpoint): void
    {
        self::assertSame(
            ['up' => false, 'body' => ''],
            (new LoopbackAgentMetricsSource($endpoint, 10))->collect(),
        );
    }

    /** @return array<string, array{string}> */
    public static function unsafeEndpoints(): array
    {
        return [
            'remote host' => ['http://example.com:9919/metrics'],
            'remote IP' => ['http://192.0.2.10:9919/metrics'],
            'unsupported TLS' => ['https://127.0.0.1:9919/metrics'],
            'credentials' => ['http://user@127.0.0.1:9919/metrics'],
            'query string' => ['http://127.0.0.1:9919/metrics?target=other'],
            'scheme relative' => ['//127.0.0.1:9919/metrics'],
            'request whitespace' => ["http://127.0.0.1:9919/metrics bad"],
        ];
    }
}

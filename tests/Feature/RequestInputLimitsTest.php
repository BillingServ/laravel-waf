<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\SecurityNotifier;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

final class RequestInputLimitsTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.ddos.enabled', false);
        $app['config']->set('laravel-waf.rules.enabled', true);
        $app['config']->set('laravel-waf.rules.mode', 'reject');
        $app['config']->set('laravel-waf.notifications.enabled', false);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(WafProtection::class)
            ->match(['GET', 'POST'], '/inspect', static fn () => response('ok'))
            ->name('inspect');
    }

    public static function overflowRequests(): array
    {
        $padding = array_fill_keys(array_map(static fn (int $i): string => 'pad'.$i, range(1, 1023)), 'a');

        return [
            // Keep this query below PHP's separate max_input_vars limit.
            'query count' => ['GET', ['max_values' => 256], array_slice($padding, 0, 255, true) + ['q' => '<script>alert(1)</script>']],
            'body count' => ['POST', [], $padding + ['q' => '<script>alert(1)</script>']],
            'value bytes' => ['POST', [], ['q' => str_repeat('a', 65536).'<script>alert(1)</script>']],
            'total bytes' => ['POST', ['max_value_bytes' => 32, 'max_total_bytes' => 64], [
                'pad1' => str_repeat('a', 32), 'pad2' => str_repeat('b', 32), 'q' => '<script>alert(1)</script>',
            ]],
            'nested body' => ['POST', ['max_depth' => 2], ['a' => ['b' => ['c' => '<script>alert(1)</script>']]]],
            'nested query' => ['GET', ['max_depth' => 2], ['a' => ['b' => ['c' => '../../../etc/passwd']]]],
        ];
    }

    #[DataProvider('overflowRequests')]
    public function test_uninspected_input_cannot_bypass_reject_mode(string $method, array $limits, array $input): void
    {
        foreach ($limits as $key => $value) {
            config()->set('laravel-waf.rules.input.'.$key, $value);
        }

        $response = $method === 'GET'
            ? $this->get('/inspect?'.http_build_query($input))
            : $this->post('/inspect', $input);

        $response->assertStatus(403)->assertHeader('X-Laravel-Waf-Blocked', 'true');
    }

    public static function normalRequests(): iterable
    {
        $nested = 'standard';
        for ($i = 0; $i < 10; $i++) {
            $nested = ['level'.$i => $nested];
        }

        $requests = [
            'large form' => array_fill(0, 1023, 'ordinary value'),
            'large text field' => ['content' => str_repeat('a', 65536)],
            'combined text fields' => [str_repeat('a', 65536), str_repeat('b', 65536), str_repeat('c', 65536), str_repeat('d', 65528)],
            'nested API data' => $nested,
            'Livewire snapshot' => ['components' => [[
                'snapshot' => json_encode(['data' => ['content' => str_repeat('ordinary text ', 2048)], 'memo' => ['id' => 'editor', 'name' => 'editor'], 'checksum' => str_repeat('a', 64)], JSON_THROW_ON_ERROR),
                'updates' => [], 'calls' => [],
            ]]],
        ];

        foreach ($requests as $name => $payload) {
            yield $name => [$payload, false];
            yield $name.' with fallback defaults' => [$payload, true];
        }
    }

    #[DataProvider('normalRequests')]
    public function test_defaults_allow_normal_larger_requests(array $payload, bool $useFallbacks): void
    {
        if ($useFallbacks) {
            config()->set('laravel-waf.rules.input', []);
        }

        $this->postJson('/inspect', $payload)->assertOk()->assertContent('ok');
    }

    public static function exactLimits(): array
    {
        return [
            'value count' => [['max_values' => 2], ['q' => 'a', 'empty' => '', 'nested' => [], 'number' => 5]],
            'value bytes' => [['max_value_bytes' => 8], ['q' => 'abcdefgh']],
            'total bytes' => [['max_value_bytes' => 8, 'max_total_bytes' => 16], ['q' => 'abcdefgh']],
            'depth' => [['max_depth' => 2], ['a' => ['b' => 'value']]],
        ];
    }

    #[DataProvider('exactLimits')]
    public function test_exact_limits_and_empty_sources_are_not_overflow(array $limits, array $input): void
    {
        foreach ($limits as $key => $value) {
            config()->set('laravel-waf.rules.input.'.$key, $value);
        }

        $this->post('/inspect', $input)->assertOk()->assertContent('ok');
    }

    public function test_overflow_is_cached_on_the_request_without_leaking_to_the_next_request(): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        $collector = app(RequestInputCollector::class);
        $overflow = Request::create('/inspect?q=hidden');
        $clean = Request::create('/inspect');

        $values = $collector->collect($overflow);
        self::assertTrue($overflow->attributes->get('laravel-waf.input_truncated'));
        $collector->collect($clean);
        self::assertFalse($clean->attributes->get('laravel-waf.input_truncated'));
        self::assertSame($values, $collector->collect($overflow));
        self::assertTrue($overflow->attributes->get('laravel-waf.input_truncated'));
        self::assertSame('hidden', $overflow->query('q'));
    }

    public static function uploadOverflows(): array
    {
        return [
            'count' => ['count'],
            'depth' => ['depth'],
            'filename bytes' => ['name'],
            'relative path bytes' => ['path'],
        ];
    }

    #[DataProvider('uploadOverflows')]
    public function test_upload_metadata_cannot_bypass_the_limits(string $kind): void
    {
        config()->set('laravel-waf.rules.input.max_value_bytes', 32);
        $file = UploadedFile::fake()->createWithContent('report.pdf', 'safe');
        $input = ['file' => $file];
        if ($kind === 'count') {
            config()->set('laravel-waf.rules.input.max_values', 2);
            $input = ['padding' => 'safe', 'file' => $file];
        } elseif ($kind === 'depth') {
            config()->set('laravel-waf.rules.input.max_depth', 1);
            $input = ['a' => ['b' => ['file' => $file]]];
        } elseif ($kind === 'name') {
            $input = ['file' => UploadedFile::fake()->createWithContent(str_repeat('a', 32).'<script>.txt', 'safe')];
        } else {
            $input = ['file' => new class($file->getPathname(), 'report.pdf', null, UPLOAD_ERR_OK, true) extends UploadedFile {
                public function getClientOriginalPath(): string
                {
                    return str_repeat('a', 32).'/../../../report.pdf';
                }
            }];
        }

        $this->post('/inspect', $input)->assertStatus(403);
    }

    public function test_multipart_file_contents_are_not_scanned_as_a_raw_body(): void
    {
        $raw = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n\r\n<script>file contents</script>\r\n--boundary--";
        $file = UploadedFile::fake()->createWithContent('report.pdf', $raw);

        $this->call('POST', '/inspect', [], [], ['file' => $file], ['CONTENT_TYPE' => 'multipart/form-data; boundary=boundary'], $raw)
            ->assertOk()->assertContent('ok');
    }

    #[DataProvider('rawContentTypes')]
    public function test_unparsed_bodies_are_inspected(string $contentType): void
    {
        $this->call('POST', '/inspect', [], [], [], ['CONTENT_TYPE' => $contentType], '<script>alert(1)</script>')
            ->assertStatus(403);
    }

    public static function rawContentTypes(): array
    {
        return [
            ['text/plain'], ['application/xml'], ['application/octet-stream'],
            ['text/plain; profile=json'], ['text/plain; profile=multipart/form-data'],
            ['application/json'], ['application/vnd.example+json'],
        ];
    }

    public function test_raw_body_overflow_is_detected_and_benign_content_is_preserved(): void
    {
        $request = Request::create('/inspect', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], 'ordinary text');
        $values = app(RequestInputCollector::class)->collect($request);
        self::assertSame('ordinary text', $request->getContent());
        self::assertCount(2, $values);
        self::assertSame('ordinary text', $values[1]->value);
        self::assertFalse($request->attributes->get('laravel-waf.input_truncated'));

        $this->call('POST', '/inspect', [], [], [], ['CONTENT_TYPE' => 'text/plain'], str_repeat('a', 65537))
            ->assertStatus(403);
    }

    public function test_empty_json_is_not_overflow_when_the_path_fills_the_budget(): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        $this->postJson('/inspect', [])->assertOk();
    }

    public static function ignoredJsonValues(): array
    {
        return [
            ['{}'], ['[]'], ['{"empty":""}'], ['{"number":5}'], ['{"empty":[]}'],
            ['{"nested":{"empty":[],"number":5,"null":null,"boolean":false}}'],
        ];
    }

    #[DataProvider('ignoredJsonValues')]
    public function test_uninspected_scalar_and_empty_values_do_not_overflow_an_exact_budget(string $json): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        config()->set('laravel-waf.rules.input.max_value_bytes', 8);
        config()->set('laravel-waf.rules.input.max_total_bytes', 8);
        $this->call('POST', '/inspect', [], [], [], ['CONTENT_TYPE' => 'application/json; charset=utf-8'], $json)
            ->assertOk();
    }

    public function test_json_media_types_still_inspect_parsed_values(): void
    {
        $this->call('POST', '/inspect', [], [], [], ['CONTENT_TYPE' => 'application/vnd.example+json; charset=utf-8'], '{"q":"<script>"}')
            ->assertStatus(403);
    }

    public function test_log_mode_records_overflow_without_blocking_the_request_or_host(): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        config()->set('laravel-waf.rules.mode', 'log');
        config()->set('laravel-waf.agent.enabled', true);
        config()->set('laravel-waf.agent.auto_block_on_finding', true);
        $this->mock(DecisionSink::class)->shouldNotReceive('block');
        config()->set('laravel-waf.notifications.enabled', true);
        $this->mock(NotificationSink::class)->shouldReceive('notify')->once()->withArgs(
            static fn (Finding $finding): bool => $finding->category === 'input'
                && $finding->rule === 'limit_exceeded'
                && !str_contains(json_encode($finding->context(), JSON_THROW_ON_ERROR), 'hidden'),
        );
        $this->app->forgetInstance(SecurityNotifier::class);

        $this->get('/inspect?q=hidden')->assertOk()->assertContent('ok');
    }

    public function test_overflow_uses_challenge_mode_and_accepts_its_pass_cookie(): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        config()->set('laravel-waf.rules.mode', 'challenge');
        $ip = '203.0.113.19';
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/inspect?q=hidden')
            ->assertStatus(429)->assertHeader('X-Laravel-Waf-Challenge', 'required');
        $pass = app(ChallengeTokenManager::class)->issuePass($ip, 600);
        $this->withUnencryptedCookie('laravel_waf_challenge', $pass)
            ->withServerVariables(['REMOTE_ADDR' => $ip])->get('/inspect?q=hidden')->assertOk();
    }

    public function test_a_challenge_pass_does_not_bypass_overflow_rejection(): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        $ip = '203.0.113.20';
        $pass = app(ChallengeTokenManager::class)->issuePass($ip, 600);
        $this->withUnencryptedCookie('laravel_waf_challenge', $pass)
            ->withServerVariables(['REMOTE_ADDR' => $ip])->get('/inspect?q=hidden')->assertStatus(403);
    }

    public function test_logged_pattern_findings_cannot_displace_the_overflow_finding(): void
    {
        config()->set('laravel-waf.rules.max_findings', 1);
        config()->set('laravel-waf.rules.input.max_values', 2);
        config()->set('laravel-waf.rules.categories.xss.action', 'log');
        $this->get('/inspect?q=%3Cscript%3E&hidden=value')->assertStatus(403);
    }

    public function test_a_logged_overflow_cannot_displace_a_rejecting_pattern(): void
    {
        config()->set('laravel-waf.rules.max_findings', 1);
        config()->set('laravel-waf.rules.input.max_values', 2);
        config()->set('laravel-waf.rules.mode', 'log');
        config()->set('laravel-waf.rules.categories.xss.action', 'reject');
        $this->get('/inspect?q=%3Cscript%3E&hidden=value')->assertStatus(403);
    }

    public function test_a_logged_route_policy_cannot_skip_collection(): void
    {
        config()->set('laravel-waf.rules.max_findings', 1);
        config()->set('laravel-waf.rules.input.max_values', 1);
        config()->set('laravel-waf.rules.categories.policy.action', 'log');
        config()->set('laravel-waf.policies.enabled', true);
        config()->set('laravel-waf.policies.routes.inspect.methods', ['POST']);
        $this->get('/inspect?q=hidden')->assertStatus(403);
    }

    public static function optOuts(): array
    {
        return [
            'rules disabled' => ['laravel-waf.rules.enabled', false],
            'route skipped' => ['laravel-waf.rules.skip_routes', ['inspect']],
            'body disabled' => ['laravel-waf.rules.input.body', false],
        ];
    }

    #[DataProvider('optOuts')]
    public function test_explicit_inspection_opt_outs_remain_supported(string $key, mixed $value): void
    {
        config()->set('laravel-waf.rules.input.max_values', 1);
        config()->set($key, $value);
        $this->post('/inspect', ['q' => '<script>'])->assertOk();
    }

    public function test_headers_and_cookies_remain_opt_in_and_field_exclusions_work(): void
    {
        config()->set('laravel-waf.rules.input.max_values', 2);
        config()->set('laravel-waf.rules.categories.xss.exclude_fields', ['content']);
        $this->withHeader('X-Probe', '<script>')->withUnencryptedCookie('probe', '<script>')
            ->post('/inspect', ['content' => '<script>'])->assertOk();
    }
}

<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Http\Middleware\SignatureProtection;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Security\Signatures\SignatureLoader;
use BillingServ\LaravelWaf\Security\Signatures\SignatureRequest;
use BillingServ\LaravelWaf\Tests\TestCase;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\RateLimiter;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;

final class SignatureTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        SignatureLoader::flush();
        $this->directory = sys_get_temp_dir().'/laravel-waf-signatures-'.bin2hex(random_bytes(6));
        mkdir($this->directory);
        config()->set('laravel-waf.signatures.paths', [$this->directory]);
        config()->set('laravel-waf.signatures.reload_interval_seconds', 0);
    }

    protected function tearDown(): void
    {
        (new Filesystem())->deleteDirectory($this->directory);
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);
        SignatureLoader::flush();
        parent::tearDown();
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 1000, 'decay_seconds' => 60]]);
        $app['config']->set('laravel-waf.notifications.enabled', false);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(WafProtection::class)
            ->match(['GET', 'POST'], '/inspect', static fn () => response('ok'))
            ->name('inspect');
        Route::middleware(WafProtection::class)
            ->get('/wp-login.php', static fn () => response('legacy redirect'))
            ->name('legacy');
        Route::post('/signature-only', static fn () => response('ok'));
    }

    public function test_core_signatures_match_the_fixture_shared_with_the_go_gate(): void
    {
        $set = app(SignatureLoader::class)->current();
        $cases = 0;

        foreach (file(__DIR__.'/../fixtures/signature-cases.tsv', FILE_IGNORE_NEW_LINES) as $line) {
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            [$expected, $method, $uri, $userAgent] = explode("\t", $line);
            $server = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri];
            if ($userAgent !== '-') {
                $server['HTTP_USER_AGENT'] = $userAgent;
            }

            [$rule] = $set->match(new SignatureRequest(new Request(server: $server), new RequestInputCollector()));
            self::assertSame($expected, $rule['id'] ?? '-', "{$method} {$uri}");
            $cases++;
        }

        self::assertGreaterThanOrEqual(40, $cases);
    }

    public function test_normalization_mirrors_the_go_gate(): void
    {
        self::assertSame('/cgi-bin/../bin', SignatureRequest::normalizePath('/cgi-bin/%%32%65%%32%65/bin'));
        self::assertSame('/a/b%', SignatureRequest::normalizePath('/A%2FB%'));
        self::assertSame('/%2e', SignatureRequest::normalizePath('/%25252e'));
        self::assertSame('/a+b', SignatureRequest::normalizePath('/a+b'));
        self::assertSame("\xadd allow_url_include=1", SignatureRequest::normalizeQuery('%ADd+Allow_URL_Include%3d1'));
    }

    public function test_php_cgi_argument_injection_is_blocked_and_banned(): void
    {
        $sink = $this->recordDecisions();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.200'])
            ->post('/inspect?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');

        self::assertSame([['203.0.113.200', 86400, 'sig:php-cgi-arg-injection']], $sink->blocks);
    }

    public function test_global_middleware_blocks_probes_for_routes_that_do_not_exist(): void
    {
        $sink = $this->recordDecisions();
        $this->app->make(Kernel::class)->pushMiddleware(SignatureProtection::class);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.201'])
            ->get('/cgi-bin/login.cgi')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');
        $this->get('/does-not-exist')->assertStatus(404);

        // The global pass marks the request so WafProtection does not ban twice.
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.202'])
            ->get('/inspect', ['User-Agent' => 'libredtail-http'])
            ->assertStatus(403);

        self::assertSame([
            ['203.0.113.201', 86400, 'sig:cgi-bin-probe'],
            ['203.0.113.202', 86400, 'sig:exploit-scanner-ua'],
        ], $sink->blocks);
    }

    public function test_a_new_rule_takes_effect_without_a_deployment(): void
    {
        $this->get('/inspect?q=cve-2026-0001')->assertOk();

        $this->writeRules('50-virtual-patch.json', [
            ['id' => 'cve-2026-0001', 'action' => 'block', 'conditions' => [
                ['target' => 'query', 'op' => 'contains', 'value' => 'CVE-2026-0001'],
            ]],
        ]);

        $this->get('/inspect?q=cve-2026-0001')->assertStatus(403);
        $this->get('/inspect?q=other')->assertOk();
    }

    public function test_an_invalid_edit_keeps_the_last_valid_rules(): void
    {
        $path = $this->writeRules('50-local.json', [
            ['id' => 'local-probe', 'conditions' => [['target' => 'path', 'op' => 'prefix', 'value' => '/inspect']]],
        ]);
        $this->get('/inspect')->assertStatus(403);

        file_put_contents($path, '{"version":1,"rules":[{"id":"local-probe"');
        touch($path, time() + 10);

        $this->get('/inspect')->assertStatus(403);
    }

    public function test_a_local_file_can_disable_a_builtin_rule(): void
    {
        $this->get('/wp-login.php')->assertStatus(403);

        $this->writeRules('00-overrides.json', [], ['wordpress-probe']);

        $this->get('/wp-login.php')->assertOk()->assertSee('legacy redirect');
    }

    public function test_global_signatures_ban_the_resolved_client_and_ignore_untrusted_forwarding(): void
    {
        $sink = $this->recordDecisions();
        $kernel = $this->app->make(Kernel::class);
        $this->app->instance(TrustProxies::class, new SignatureTrustedProxies());
        $kernel->prependMiddleware(TrustProxies::class);
        $kernel->pushMiddleware(SignatureProtection::class);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.10'])
            ->get('/cgi-bin/login.cgi', ['X-Forwarded-For' => '203.0.113.77'])->assertStatus(403);
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.11'])
            ->get('/cgi-bin/login.cgi', ['X-Forwarded-For' => '203.0.113.88'])->assertStatus(403);

        self::assertSame(['203.0.113.77', '198.51.100.11'], array_column($sink->blocks, 0));
    }

    public function test_regex_errors_fail_closed_in_both_middleware_paths_without_banning(): void
    {
        $sink = $this->recordDecisions();
        $limit = ini_set('pcre.backtrack_limit', '1000');
        try {
            foreach ([false, true] as $global) {
                if ($global) {
                    $this->app->make(Kernel::class)->pushMiddleware(SignatureProtection::class);
                }
                foreach ([false, true] as $negate) {
                    $this->writeRules('50-local.json', [[
                        'id' => 'body-patch', 'action' => 'ban', 'conditions' => [[
                            'target' => 'body', 'op' => 'regex', 'value' => '^(a+)+$|evil', 'negate' => $negate,
                        ]],
                    ]]);
                    $this->post('/inspect', ['payload' => str_repeat('a', 40).'!evil'])
                        ->assertStatus(503)->assertHeader('Retry-After', '5');
                }
            }
            self::assertSame([], $sink->blocks);
        } finally {
            ini_set('pcre.backtrack_limit', (string) $limit);
        }
        $this->writeRules('50-local.json', [[
            'id' => 'body-patch', 'conditions' => [['target' => 'body', 'op' => 'regex', 'value' => 'evil']],
        ]]);
        $this->post('/inspect', ['payload' => 'evil'])->assertStatus(403);
        $this->post('/inspect', ['payload' => 'ordinary text'])->assertOk();
    }

    public function test_log_only_regex_errors_remain_observations(): void
    {
        $this->writeRules('50-local.json', [[
            'id' => 'watch', 'action' => 'log', 'conditions' => [[
                'target' => 'body', 'op' => 'regex', 'value' => '^(a+)+$|evil',
            ]],
        ]]);
        $this->post('/inspect', ['payload' => str_repeat('a', 40).'!evil'])->assertOk();
    }

    public function test_global_body_signatures_do_not_allow_payloads_hidden_after_input_limits(): void
    {
        $this->app->make(Kernel::class)->pushMiddleware(SignatureProtection::class);
        config()->set('laravel-waf.rules.input.max_value_bytes', 64);
        $this->writeRules('local.json', [[
            'id' => 'body-patch', 'conditions' => [['target' => 'body', 'op' => 'contains', 'value' => 'evil']],
        ]]);
        $this->post('/signature-only', ['payload' => 'evil'])->assertStatus(403);
        $this->post('/signature-only', ['padding' => str_repeat('a', 65), 'payload' => 'evil'])->assertStatus(503);
        $this->post('/signature-only', ['payload' => 'ordinary text'])->assertOk();
    }

    public function test_last_valid_documents_survive_a_request_state_reset_using_file_cache(): void
    {
        config()->set('cache.stores.signature-state', ['driver' => 'file', 'path' => $this->directory.'/cache']);
        config()->set('cache.default', 'signature-state');
        $path = $this->writeRules('50-local.json', [[
            'id' => 'local-patch', 'conditions' => [['target' => 'path', 'op' => 'equals', 'value' => '/inspect']],
        ]]);
        $this->get('/inspect')->assertStatus(403);
        file_put_contents($path, '{broken');
        SignatureLoader::flush();
        $this->app->forgetInstance(SignatureLoader::class);
        $this->app->forgetInstance(\BillingServ\LaravelWaf\Security\Rules\SignatureRule::class);
        $this->app->forgetInstance(\BillingServ\LaravelWaf\Security\RequestRuleEngine::class);
        $this->get('/inspect')->assertStatus(403);
        $this->get('/wp-login.php')->assertStatus(403);
    }

    public function test_unavailable_configured_roots_keep_rules_but_deleted_dropins_are_removed(): void
    {
        config()->set('laravel-waf.signatures.builtin', false);
        $path = $this->writeRules('50-local.json', [[
            'id' => 'local-patch', 'conditions' => [['target' => 'path', 'op' => 'equals', 'value' => '/inspect']],
        ]]);
        config()->set('laravel-waf.signatures.paths', [$path]);
        $loader = app(SignatureLoader::class);
        self::assertCount(1, $loader->current()->rules);
        unlink($path);
        SignatureLoader::flush();
        self::assertCount(1, $loader->current()->rules);

        $root = $this->directory.'/dropins';
        mkdir($root);
        file_put_contents($root.'/local.json', json_encode(['version' => 1, 'rules' => [[
            'id' => 'directory-patch', 'conditions' => [['target' => 'path', 'op' => 'equals', 'value' => '/inspect']],
        ]]]));
        config()->set('laravel-waf.signatures.paths', [$root]);
        self::assertCount(1, $loader->current()->rules);
        rename($root, $root.'.offline');
        SignatureLoader::flush();
        self::assertCount(1, $loader->current()->rules);
        rename($root.'.offline', $root);
        unlink($root.'/local.json');
        self::assertCount(0, $loader->current()->rules);
    }

    public function test_invalid_first_version_never_becomes_an_empty_successful_reload(): void
    {
        file_put_contents($this->directory.'/bad.json', '{broken');
        $this->get('/inspect')->assertStatus(503);
        $this->get('/inspect')->assertStatus(503);
    }

    public function test_same_size_edit_with_unchanged_timestamp_is_loaded(): void
    {
        config()->set('laravel-waf.signatures.builtin', false);
        $path = $this->writeRules('local.json', [[
            'id' => 'local', 'conditions' => [['target' => 'path', 'op' => 'equals', 'value' => '/before']],
        ]]);
        $loader = app(SignatureLoader::class);
        self::assertSame('/before', $loader->current()->rules[0]['conditions'][0]['values'][0]);
        $stamp = filemtime($path);
        file_put_contents($path, str_replace('/before', '/afterx', file_get_contents($path)));
        touch($path, $stamp);
        self::assertSame('/afterx', $loader->current()->rules[0]['conditions'][0]['values'][0]);
    }

    public function test_unchanged_invalid_versions_keep_error_deduplication_until_repaired(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning');
        $this->app->instance(LoggerInterface::class, $logger);
        $path = $this->writeRules('local.json', [[
            'id' => 'local', 'conditions' => [['target' => 'path', 'op' => 'equals', 'value' => '/inspect']],
        ]]);
        $loader = app(SignatureLoader::class);
        $loader->current();
        file_put_contents($path, '{broken');
        $loader->current();
        $loader->current();
        touch($path, time() + 20);
        $loader->current();
    }

    public function test_all_log_matches_are_recorded_once_without_displacing_a_block(): void
    {
        $metrics = new RecordingSignatureMetricsSink();
        $this->app->instance(MetricsSink::class, $metrics);
        $this->app->forgetInstance(\BillingServ\LaravelWaf\Support\MetricsRecorder::class);
        config()->set('laravel-waf.rules.max_findings', 1);
        foreach ([false, true] as $global) {
            if ($global) {
                $this->app->make(Kernel::class)->pushMiddleware(SignatureProtection::class);
            }
            foreach ([false, true] as $blocked) {
                $condition = [['target' => 'path', 'op' => 'equals', 'value' => '/inspect']];
                $rules = [
                    ['id' => 'watch-one', 'action' => 'log', 'conditions' => $condition],
                    ['id' => 'watch-two', 'action' => 'log', 'conditions' => $condition],
                ];
                if ($blocked) {
                    $rules[] = ['id' => 'deny', 'conditions' => $condition];
                }
                $this->writeRules('local.json', $rules);
                $metrics->rules = [];
                $this->get('/inspect')->assertStatus($blocked ? 403 : 200);
                self::assertSame($blocked ? ['watch-one', 'watch-two', 'deny'] : ['watch-one', 'watch-two'], $metrics->rules);
            }
        }
    }

    public function test_behavior_findings_cannot_displace_an_enforcing_signature(): void
    {
        $sink = $this->recordDecisions();
        config()->set('laravel-waf.rules.max_findings', 1);
        config()->set('laravel-waf.behavior.enabled', true);
        config()->set('laravel-waf.behavior.thresholds', ['client_error' => 1]);
        config()->set('laravel-waf.behavior.action', 'log');
        $ip = '203.0.113.90';
        app(RateLimiter::class)->hit(RateLimitKey::behavior($ip, 'client_error'), 60);
        $this->writeRules('local.json', [[
            'id' => 'body-patch', 'action' => 'ban', 'conditions' => [['target' => 'body', 'op' => 'contains', 'value' => 'evil']],
        ]]);
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->post('/inspect', ['payload' => 'evil'])->assertStatus(403);
        self::assertSame([[$ip, 3600, 'sig:body-patch']], $sink->blocks);
    }

    public function test_body_rules_and_log_only_rules_are_evaluated_inside_laravel(): void
    {
        $sink = $this->recordDecisions();
        $this->writeRules('50-local.json', [
            ['id' => 'watch-exports', 'action' => 'log', 'conditions' => [
                ['target' => 'path', 'op' => 'equals', 'value' => '/inspect'],
            ]],
            ['id' => 'php-object-body', 'action' => 'ban', 'ttl' => 600, 'conditions' => [
                ['target' => 'method', 'op' => 'equals', 'value' => 'POST'],
                ['target' => 'body', 'op' => 'regex', 'value' => 'o:\d+:"[a-z_\\\\]+"'],
            ]],
        ]);

        $this->get('/inspect')->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.203'])
            ->post('/inspect', ['payload' => 'O:8:"stdClass":0:{}'])
            ->assertStatus(403);

        self::assertSame([['203.0.113.203', 600, 'sig:php-object-body']], $sink->blocks);
    }

    public function test_block_signatures_do_not_trigger_the_generic_finding_auto_block(): void
    {
        $sink = $this->recordDecisions();
        config()->set('laravel-waf.agent.auto_block_on_finding', true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.204'])
            ->get('/inspect', ['User-Agent' => 'x'])
            ->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.204'])
            ->get('/wp-login.php')
            ->assertStatus(403);

        self::assertSame([], $sink->blocks);
    }

    public function test_query_parameter_names_are_inspected_by_the_built_in_rules(): void
    {
        config()->set('laravel-waf.signatures.enabled', false);
        $this->app->forgetInstance(\BillingServ\LaravelWaf\Security\RequestRuleEngine::class);

        $this->post('/inspect?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input')
            ->assertStatus(403);
        $this->get('/inspect?filter_status=paid&sort.order=desc')->assertOk();
    }

    public function test_invalid_documents_are_rejected(): void
    {
        $invalid = [
            'trailing data' => '{"version":1,"rules":[]}garbage',
            'second document' => '{"version":1,"rules":[]}{"version":1}',
            'version' => '{"version":2,"rules":[]}',
            'unknown field' => '{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"contains","valeus":["x"]}]}]}',
            'bad id' => '{"version":1,"rules":[{"id":"Bad ID","conditions":[{"target":"path","op":"contains","value":"x"}]}]}',
            'bad action' => '{"version":1,"rules":[{"id":"a","action":"drop","conditions":[{"target":"path","op":"contains","value":"x"}]}]}',
            'bad target' => '{"version":1,"rules":[{"id":"a","conditions":[{"target":"cookie","op":"contains","value":"x"}]}]}',
            'bad op' => '{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"like","value":"x"}]}]}',
            'bad regex' => '{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"regex","value":"(?<=x)"}]}]}',
            'ttl' => '{"version":1,"rules":[{"id":"a","action":"ban","ttl":90000,"conditions":[{"target":"path","op":"contains","value":"x"}]}]}',
            'no conditions' => '{"version":1,"rules":[{"id":"a","conditions":[]}]}',
            'empty contains' => '{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"contains","value":""}]}]}',
            'disabled bad' => '{"version":1,"rules":[{"id":"a","enabled":false,"conditions":[{"target":"path","op":"regex","value":"("}]}]}',
        ];

        foreach ($invalid as $name => $document) {
            try {
                SignatureLoader::parse($document);
                self::fail("{$name}: expected a validation error");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }

        self::assertCount(14, SignatureLoader::parse((string) file_get_contents(SignatureLoader::BUILTIN_PATH))['rules']);
    }

    private function recordDecisions(): RecordingSignatureDecisionSink
    {
        config()->set('laravel-waf.agent.enabled', true);
        $sink = new RecordingSignatureDecisionSink();
        $this->app->instance(DecisionSink::class, $sink);

        return $sink;
    }

    private function writeRules(string $name, array $rules, array $disable = []): string
    {
        $path = $this->directory.'/'.$name;
        $document = ['version' => 1, 'rules' => $rules];
        if ($disable !== []) {
            $document['disable'] = $disable;
        }
        file_put_contents($path, json_encode($document, JSON_THROW_ON_ERROR));
        touch($path, time() + random_int(1, 1000));

        return $path;
    }
}

final class RecordingSignatureDecisionSink implements DecisionSink
{
    /** @var array<int, array{0: string, 1: int, 2: string}> */
    public array $blocks = [];

    public function block(string $ip, int $ttlSeconds, string $reason): void
    {
        $this->blocks[] = [$ip, $ttlSeconds, $reason];
    }
}

final class SignatureTrustedProxies extends TrustProxies
{
    protected $proxies = ['198.51.100.10'];
    protected $headers = Request::HEADER_X_FORWARDED_FOR;
}

final class RecordingSignatureMetricsSink implements MetricsSink
{
    public array $rules = [];

    public function increment(string $name, array $labels = []): void
    {
        if ($name === 'findings' && ($labels['category'] ?? '') === 'signature') {
            $this->rules[] = $labels['rule'];
        }
    }

    public function observe(string $name, float $value, array $labels = []): void
    {
    }
}

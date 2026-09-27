<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Security\BehaviorTracker;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Cache\RateLimiter;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PDOException;
use RuntimeException;

final class BehaviorTrackerDatabaseCacheTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('cache.default', 'database');
        $app['config']->set('cache.stores.database', [
            'driver' => 'database',
            'connection' => 'testing',
            'table' => 'cache',
        ]);
        $app['config']->set('laravel-waf.behavior.thresholds', [
            '404' => 2,
            '405' => 2,
            '401' => 2,
            '403' => 2,
            'client_error' => 2,
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('cache', static function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->text('value');
            $table->integer('expiration');
        });
        $this->freezeTime();
    }

    public function test_all_behavior_counters_are_read_in_one_query(): void
    {
        $tracker = $this->app->make(BehaviorTracker::class);
        DB::enableQueryLog();

        self::assertNull($tracker->inspect($this->request()));

        $queries = DB::getQueryLog();
        self::assertCount(1, $queries);
        self::assertStringContainsString('select', $queries[0]['query']);
        self::assertCount(5, $queries[0]['bindings']);
    }

    public function test_nonzero_counters_below_the_threshold_are_still_batched(): void
    {
        foreach (['404', '405', '401', '403', 'client_error'] as $kind) {
            $this->app->make(RateLimiter::class)->hit($this->key($kind), 60);
        }
        DB::enableQueryLog();

        self::assertNull($this->app->make(BehaviorTracker::class)->inspect($this->request()));
        self::assertCount(1, DB::getQueryLog());
    }

    public function test_a_reached_threshold_still_triggers_a_finding(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 60);
        $limiter->hit($this->key('403'), 60);

        $finding = $this->app->make(BehaviorTracker::class)->inspect($this->request());

        self::assertNotNull($finding);
        self::assertSame('repeated_403', $finding->rule);
    }

    public function test_stale_counters_are_reset_when_their_timer_is_missing(): void
    {
        cache()->put($this->key('404'), 20, 3600);

        self::assertNull($this->app->make(BehaviorTracker::class)->inspect($this->request()));
        self::assertSame(0, $this->app->make(RateLimiter::class)->attempts($this->key('404')));
    }

    public function test_expired_counters_do_not_trigger_a_finding(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('404'), 60);
        $limiter->hit($this->key('404'), 60);

        $this->travel(61)->seconds();

        self::assertNull($this->app->make(BehaviorTracker::class)->inspect($this->request()));
    }

    public function test_inspections_do_not_reuse_counts_from_an_earlier_request(): void
    {
        $tracker = $this->app->make(BehaviorTracker::class);
        self::assertNull($tracker->inspect($this->request()));

        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('401'), 60);
        $limiter->hit($this->key('401'), 60);

        self::assertSame('repeated_401', $tracker->inspect($this->request())?->rule);
    }

    public function test_batch_reads_use_the_configured_limiter_store(): void
    {
        config()->set('cache.default', 'array');
        config()->set('cache.limiter', 'database');
        $this->app->forgetInstance(RateLimiter::class);
        $this->app->forgetInstance(BehaviorTracker::class);

        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('401'), 60);
        $limiter->hit($this->key('401'), 60);

        self::assertSame('repeated_401', $this->app->make(BehaviorTracker::class)->inspect($this->request())?->rule);
    }

    public function test_disabled_thresholds_do_not_read_the_cache(): void
    {
        config()->set('laravel-waf.behavior.thresholds', ['404' => 0, '401' => -1]);
        DB::enableQueryLog();

        self::assertNull($this->app->make(BehaviorTracker::class)->inspect($this->request()));
        self::assertSame([], DB::getQueryLog());
    }

    public function test_a_stale_counter_does_not_hide_a_later_reached_threshold(): void
    {
        cache()->put($this->key('404'), 20, 3600);
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 60);
        $limiter->hit($this->key('403'), 60);

        self::assertSame('repeated_403', $this->app->make(BehaviorTracker::class)->inspect($this->request())?->rule);
        self::assertSame(0, $limiter->attempts($this->key('404')));
    }

    public function test_alert_cooldowns_are_preserved(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('404'), 60);
        $limiter->hit($this->key('404'), 60);
        $tracker = $this->app->make(BehaviorTracker::class);

        self::assertNotNull($tracker->inspect($this->request()));
        self::assertNotNull($tracker->inspect($this->request()));
        self::assertSame(1, $limiter->attempts(RateLimitKey::behaviorAlert('203.0.113.10', '404')));
    }

    public function test_cache_failures_preserve_fail_open_behavior(): void
    {
        Schema::drop('cache');

        self::assertNull($this->app->make(BehaviorTracker::class)->inspect($this->request()));
    }

    public function test_first_behavior_alert_batches_threshold_timer_and_cooldown_queries(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 60);
        $limiter->hit($this->key('403'), 60);
        DB::enableQueryLog();

        self::assertSame('repeated_403', $this->app->make(BehaviorTracker::class)->inspect($this->request())?->rule);

        // Initial counter read, locked read, reserve missing alert rows,
        // locked reread and one write for the alert counter and timer.
        self::assertCount(5, DB::getQueryLog());
        self::assertSame(1, $limiter->attempts(RateLimitKey::behaviorAlert('203.0.113.10', '403')));
        self::assertSame(2, $limiter->attempts($this->key('403')));
    }

    public function test_active_alert_cooldowns_need_only_two_reads_and_preserve_the_window(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 600);
        $limiter->hit($this->key('403'), 600);
        $tracker = $this->app->make(BehaviorTracker::class);
        self::assertNotNull($tracker->inspect($this->request()));
        $this->travel(10)->seconds();
        DB::enableQueryLog();

        self::assertSame('repeated_403', $tracker->inspect($this->request())?->rule);

        $queries = DB::getQueryLog();
        self::assertCount(2, $queries);
        foreach ($queries as $query) {
            self::assertStringStartsWith('select', $query['query']);
        }
        $alertKey = RateLimitKey::behaviorAlert('203.0.113.10', '403');
        self::assertSame(1, $limiter->attempts($alertKey));
        self::assertSame(50, $limiter->availableIn($alertKey));
    }

    public function test_expired_alert_cooldowns_are_renewed_with_one_batched_write(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 600);
        $limiter->hit($this->key('403'), 600);
        $alertKey = RateLimitKey::behaviorAlert('203.0.113.10', '403');
        $limiter->hit($alertKey, 1);
        $this->travel(2)->seconds();
        DB::enableQueryLog();

        self::assertSame('repeated_403', $this->app->make(BehaviorTracker::class)->inspect($this->request())?->rule);

        // Counter prefetch, one locked read and one write, without per-key cleanup.
        self::assertCount(3, DB::getQueryLog());
        self::assertSame(1, $limiter->attempts($alertKey));
        self::assertSame(60, $limiter->availableIn($alertKey));
    }

    public function test_alert_metrics_are_emitted_once_after_a_successful_retry(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 600);
        $limiter->hit($this->key('403'), 600);
        $alertKey = RateLimitKey::behaviorAlert('203.0.113.10', '403');
        $limiter->hit($alertKey, 1);
        $this->travel(2)->seconds();
        $sink = $this->createMock(MetricsSink::class);
        $sink->expects(self::once())->method('increment')
            ->with('behavior_events', ['kind' => '403', 'outcome' => 'alert', 'route' => 'unnamed'])
            ->willReturnCallback(static function (): void {
                self::assertSame(0, DB::transactionLevel());
            });
        $this->app->instance(MetricsSink::class, $sink);
        $this->app->forgetInstance(MetricsRecorder::class);
        $this->app->forgetInstance(BehaviorTracker::class);
        $writes = 0;
        DB::connection()->beforeExecuting(static function (string $query) use (&$writes): void {
            if (str_starts_with($query, 'insert') && ++$writes === 1) {
                throw new PDOException('database is locked');
            }
        });

        self::assertSame('repeated_403', $this->app->make(BehaviorTracker::class)->inspect($this->request())?->rule);
        self::assertSame(2, $writes);
        self::assertSame(1, $limiter->attempts($alertKey));
    }

    public function test_failed_alert_writes_do_not_emit_alert_metrics(): void
    {
        $limiter = $this->app->make(RateLimiter::class);
        $limiter->hit($this->key('403'), 600);
        $limiter->hit($this->key('403'), 600);
        $alertKey = RateLimitKey::behaviorAlert('203.0.113.10', '403');
        $limiter->hit($alertKey, 1);
        $this->travel(2)->seconds();
        $sink = $this->createMock(MetricsSink::class);
        $sink->expects(self::once())->method('increment')->with('errors', ['component' => 'behavior_tracker']);
        $this->app->instance(MetricsSink::class, $sink);
        $this->app->forgetInstance(MetricsRecorder::class);
        $this->app->forgetInstance(BehaviorTracker::class);
        DB::connection()->beforeExecuting(static function (string $query): void {
            if (str_starts_with($query, 'insert')) {
                throw new RuntimeException('Simulated cache write failure');
            }
        });

        self::assertNull($this->app->make(BehaviorTracker::class)->inspect($this->request()));
        self::assertSame(0, $limiter->attempts($alertKey));
        self::assertSame(2, $limiter->attempts($this->key('403')));
    }

    public function test_tenant_switches_keep_batch_reads_and_recorded_counts_together(): void
    {
        $earlyLimiter = $this->app->make(RateLimiter::class);
        $tracker = $this->app->make(BehaviorTracker::class);
        Schema::create('tenant_cache', static function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->text('value');
            $table->integer('expiration');
        });

        config()->set('cache.stores.database.table', 'tenant_cache');
        app('cache')->forgetDriver('database');

        $tracker->record($this->request(), response('', 401));
        $tracker->record($this->request(), response('', 401));

        self::assertSame(0, $earlyLimiter->attempts($this->key('401')));
        self::assertSame('repeated_401', $tracker->inspect($this->request())?->rule);
        self::assertSame(2, cache()->get($this->key('401')));

        config()->set('cache.stores.database.table', 'cache');
        app('cache')->forgetDriver('database');
        self::assertNull($tracker->inspect($this->request()));
    }

    private function request(): Request
    {
        return Request::create('/metrics', 'POST', server: ['REMOTE_ADDR' => '203.0.113.10']);
    }

    private function key(string $kind): string
    {
        return RateLimitKey::behavior('203.0.113.10', $kind);
    }
}

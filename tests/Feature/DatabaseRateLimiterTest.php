<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\RateLimiter;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Cache\RateLimiter as LaravelRateLimiter;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PDOException;
use RuntimeException;

final class DatabaseRateLimiterTest extends TestCase
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
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(WafProtection::class)->get('/limited', static fn () => response('ok'))->name('limited');
        Route::middleware(WafProtection::class)->get('/unauthorized', static fn () => response('', 401))->name('unauthorized');
        Route::middleware(WafProtection::class)->post('/api/v1/customer/check', static fn () => response('', 410))->name('deprecated');
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

    public function test_warm_ddos_buckets_share_one_read_and_one_commit(): void
    {
        $this->get('/limited')->assertOk();
        DB::enableQueryLog();
        $commits = 0;
        Event::listen(TransactionCommitted::class, static function ($event) use (&$commits): void {
            if ($event->connection->transactionLevel() === 0) {
                $commits++;
            }
        });

        $this->get('/limited')->assertOk()->assertHeader('X-RateLimit-Remaining', '0');

        // One behavior read and one locked read for all buckets and timers.
        $selects = array_filter(DB::getQueryLog(), static fn (array $query): bool => str_starts_with($query['query'], 'select'));
        self::assertCount(2, $selects);
        self::assertCount(3, DB::getQueryLog());
        self::assertSame(1, $commits);
        $this->get('/limited')->assertStatus(429)->assertHeader('Retry-After');
    }

    public function test_cold_ddos_buckets_are_initialized_in_one_batch(): void
    {
        DB::enableQueryLog();

        $this->get('/limited')->assertOk()->assertHeader('X-RateLimit-Remaining', '1');

        // Behavior inspection, locked read, bulk reservation, locked re-read,
        // and a single write of all three counters and their timers.
        self::assertCount(5, DB::getQueryLog());
        self::assertSame(6, DB::table('cache')->count());
        self::assertSame(0, DB::table('cache')->where('expiration', 0)->count());
        $limiter = app(RateLimiter::class);
        foreach (['global', 'route', 'burst'] as $scope) {
            $key = RateLimitKey::for($scope, '127.0.0.1', $scope === 'route' ? 'limited' : '');
            self::assertSame(1, $limiter->attempts($key));
            self::assertSame($scope === 'burst' ? 5 : 60, $limiter->availableIn($key));
        }
    }

    public function test_expired_ddos_buckets_are_reset_in_one_batch(): void
    {
        $this->get('/limited')->assertOk();
        $this->travel(61)->seconds();
        DB::enableQueryLog();

        $this->get('/limited')->assertOk()->assertHeader('X-RateLimit-Remaining', '1');

        self::assertCount(3, DB::getQueryLog());
        self::assertSame(1, app(RateLimiter::class)->attempts(RateLimitKey::for('global', '127.0.0.1')));
    }

    public function test_expiring_the_burst_bucket_does_not_restart_the_minute_window(): void
    {
        $this->get('/limited')->assertOk();
        $this->travel(6)->seconds();
        DB::enableQueryLog();

        $this->get('/limited')->assertOk()->assertHeader('X-RateLimit-Remaining', '0');

        self::assertCount(3, DB::getQueryLog());
        $limiter = app(RateLimiter::class);
        self::assertSame(2, $limiter->attempts(RateLimitKey::for('global', '127.0.0.1')));
        self::assertSame(54, $limiter->availableIn(RateLimitKey::for('global', '127.0.0.1')));
        self::assertSame(1, $limiter->attempts(RateLimitKey::for('burst', '127.0.0.1')));
        self::assertSame(5, $limiter->availableIn(RateLimitKey::for('burst', '127.0.0.1')));
    }

    public function test_cold_rejection_does_not_initialize_later_buckets(): void
    {
        config()->set('laravel-waf.ddos.global.max_attempts', 1);
        $limiter = app(RateLimiter::class);
        $limiter->hit(RateLimitKey::for('global', '127.0.0.1'), 60);

        $this->get('/limited')->assertStatus(429);

        foreach (['route', 'burst'] as $scope) {
            $key = RateLimitKey::for($scope, '127.0.0.1', $scope === 'route' ? 'limited' : '');
            self::assertNull(cache()->get($key));
            self::assertNull(cache()->get($key.':timer'));
        }
        self::assertSame(0, DB::table('cache')->where('expiration', 0)->count());
    }

    public function test_a_competing_initializer_is_read_back_before_incrementing(): void
    {
        $interleaved = false;
        DB::connection()->beforeExecuting(static function (string $query) use (&$interleaved): void {
            if (!$interleaved && str_starts_with($query, 'insert or ignore')) {
                $interleaved = true;
                cache()->put('counter', 3, 30);
                cache()->put('counter:timer', now()->timestamp + 30, 30);
            }
        });

        app(RateLimiter::class)->batch(['counter'], static function (LaravelRateLimiter $batch): void {
            self::assertSame(3, $batch->attempts('counter'));
            self::assertSame(4, $batch->hit('counter', 60));
            self::assertSame(30, $batch->availableIn('counter'));
        });

        self::assertTrue($interleaved);
        self::assertSame(4, cache()->get('counter'));
    }

    public function test_cold_write_retries_do_not_leave_reservations_or_double_counts(): void
    {
        $writes = 0;
        DB::connection()->beforeExecuting(static function (string $query) use (&$writes): void {
            if (str_starts_with($query, 'insert into') && ++$writes === 1) {
                throw new PDOException('database is locked');
            }
        });

        app(RateLimiter::class)->hitMany(['first', 'second'], 60);

        self::assertSame(2, $writes);
        self::assertSame(1, cache()->get('first'));
        self::assertSame(1, cache()->get('second'));
        self::assertSame(4, DB::table('cache')->count());
        self::assertSame(0, DB::table('cache')->where('expiration', 0)->count());
    }

    public function test_non_integer_fallback_cleans_up_unused_reservations(): void
    {
        cache()->put('first', '3', 60);
        app(RateLimiter::class)->hitMany(['first', 'second'], 60);

        self::assertSame(4, cache()->get('first'));
        self::assertSame(1, cache()->get('second'));
        self::assertSame(4, DB::table('cache')->count());
        self::assertSame(0, DB::table('cache')->where('expiration', 0)->count());
    }

    public function test_clearing_and_rehitting_inside_a_batch_starts_a_new_window(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('counter', 60);
        $this->travel(5)->seconds();

        $limiter->batch(['counter'], static function (LaravelRateLimiter $batch): void {
            $batch->hit('counter', 60);
            $batch->clear('counter');
            self::assertSame(0, $batch->attempts('counter'));
            self::assertSame(0, $batch->availableIn('counter'));
            self::assertSame(1, $batch->hit('counter', 10));
        });

        self::assertSame(1, $limiter->attempts('counter'));
        self::assertSame(10, $limiter->availableIn('counter'));
    }

    public function test_counter_batches_preserve_different_windows_and_stale_timer_resets(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->batch(['minute', 'burst'], static function (LaravelRateLimiter $batch): void {
            $batch->hit('minute', 60);
            $batch->hit('burst', 5);
        });

        $this->travel(6)->seconds();
        self::assertSame(1, $limiter->attempts('minute'));
        self::assertSame(0, $limiter->attempts('burst'));
        cache()->put('burst', 100, 3600);

        $limiter->batch(['minute', 'burst'], static function (LaravelRateLimiter $batch): void {
            self::assertFalse($batch->tooManyAttempts('burst', 2));
            self::assertSame(1, $batch->hit('burst', 5));
            self::assertSame(2, $batch->hit('minute', 60));
        });

        self::assertSame(54, $limiter->availableIn('minute'));
        self::assertSame(5, $limiter->availableIn('burst'));
    }

    public function test_unauthorized_responses_batch_both_ddos_and_behavior_writes(): void
    {
        $this->get('/unauthorized')->assertUnauthorized();
        DB::enableQueryLog();
        $commits = 0;
        Event::listen(TransactionCommitted::class, static function ($event) use (&$commits): void {
            if ($event->connection->transactionLevel() === 0) {
                $commits++;
            }
        });

        $this->get('/unauthorized')->assertUnauthorized();

        $selects = array_filter(DB::getQueryLog(), static fn (array $query): bool => str_starts_with($query['query'], 'select'));
        self::assertCount(3, $selects);
        self::assertCount(5, DB::getQueryLog());
        self::assertSame(2, $commits);
    }

    public function test_increment_reads_the_current_value_under_the_batch_lock(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('counter', 60);

        self::assertSame(1, $limiter->attemptsMany(['counter'])['counter']);
        // Another writer changes the count after an earlier unlocked read.
        self::assertSame(2, $limiter->hit('counter', 60));
        $limiter->batch(['counter'], static function (LaravelRateLimiter $batch): void {
            self::assertSame(3, $batch->hit('counter', 60));
        });

        self::assertSame(3, $limiter->attempts('counter'));
    }

    public function test_deprecated_api_responses_do_not_repeat_locked_reads_and_updates_per_bucket(): void
    {
        $this->post('/api/v1/customer/check')->assertStatus(410);
        DB::enableQueryLog();

        $this->post('/api/v1/customer/check')->assertStatus(410);

        // Behavior inspection plus one read/write pair per DDoS/response batch.
        $queries = DB::getQueryLog();
        self::assertCount(5, $queries);
        self::assertCount(3, array_filter($queries, static fn (array $query): bool => str_starts_with($query['query'], 'select')));
        self::assertCount(2, array_filter($queries, static fn (array $query): bool => str_starts_with($query['query'], 'insert')));
        self::assertSame(2, app(RateLimiter::class)->attempts(RateLimitKey::behavior('127.0.0.1', 'client_error')));
    }

    public function test_warm_batches_preserve_expirations_and_repeated_hits(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->batch(['minute', 'burst'], static function (LaravelRateLimiter $batch): void {
            $batch->hit('minute', 60);
            $batch->hit('burst', 5);
        });
        $this->travel(2)->seconds();
        DB::enableQueryLog();

        $limiter->batch(['minute', 'burst', 'minute'], static function (LaravelRateLimiter $batch): void {
            self::assertSame(2, $batch->hit('minute', 60));
            self::assertSame(3, $batch->hit('minute', 60));
            self::assertSame(2, $batch->hit('burst', 5));
            self::assertSame(58, $batch->availableIn('minute'));
            self::assertSame(3, $batch->availableIn('burst'));
            self::assertTrue($batch->tooManyAttempts('minute', 3));
        });

        self::assertCount(2, DB::getQueryLog());
        self::assertSame(3, $limiter->attempts('minute'));
        self::assertSame(2, $limiter->attempts('burst'));
        $this->travel(4)->seconds();
        self::assertSame(0, $limiter->attempts('burst'));
        self::assertSame(3, $limiter->attempts('minute'));
        self::assertSame(54, $limiter->availableIn('minute'));
    }

    public function test_rejection_leaves_later_buckets_untouched(): void
    {
        $this->get('/limited')->assertOk();
        $this->get('/limited')->assertOk();
        $this->get('/limited')->assertStatus(429);

        $limiter = app(RateLimiter::class);
        self::assertSame(3, $limiter->attempts(RateLimitKey::for('global', '127.0.0.1')));
        self::assertSame(2, $limiter->attempts(RateLimitKey::for('route', '127.0.0.1', 'limited')));
        self::assertSame(2, $limiter->attempts(RateLimitKey::for('burst', '127.0.0.1')));
    }

    public function test_pending_counts_are_flushed_before_falling_back_at_an_expiry_boundary(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('minute', 60);
        $limiter->hit('burst', 1);

        $limiter->batch(['minute', 'burst'], function (LaravelRateLimiter $batch): void {
            self::assertSame(2, $batch->hit('minute', 60));
            self::assertSame(2, $batch->hit('burst', 1));
            $this->travel(2)->seconds();
            self::assertSame(3, $batch->hit('minute', 60));
            self::assertSame(0, $batch->attempts('burst'));
            self::assertSame(1, $batch->hit('burst', 5));
        });

        self::assertSame(3, $limiter->attempts('minute'));
        self::assertSame(58, $limiter->availableIn('minute'));
        self::assertSame(1, $limiter->attempts('burst'));
        self::assertSame(5, $limiter->availableIn('burst'));
    }

    public function test_resetting_a_warm_counter_does_not_discard_other_pending_increments(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hitMany(['first', 'second'], 60);
        $limiter->batch(['first', 'second'], static function (LaravelRateLimiter $batch): void {
            $batch->hit('first', 60);
            $batch->hit('second', 60);
            $batch->resetAttempts('first');
            self::assertSame(1, $batch->hit('first', 60));
        });

        self::assertSame(1, $limiter->attempts('first'));
        self::assertSame(2, $limiter->attempts('second'));
    }

    public function test_a_zero_counter_keeps_laravels_expiration_repair(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('counter', 60);
        cache()->put('counter', 0, 1);

        $limiter->batch(['counter'], static function (LaravelRateLimiter $batch): void {
            self::assertSame(1, $batch->hit('counter', 60));
        });

        $this->travel(2)->seconds();
        self::assertSame(1, $limiter->attempts('counter'));
        self::assertSame(58, $limiter->availableIn('counter'));
    }

    public function test_bulk_writes_use_the_selected_table_and_prefix(): void
    {
        Schema::create('tenant_cache', static function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->text('value');
            $table->integer('expiration');
        });
        config()->set('cache.stores.database.table', 'tenant_cache');
        config()->set('cache.stores.database.prefix', 'tenant:42:');
        app('cache')->forgetDriver('database');
        $limiter = app(RateLimiter::class);
        $limiter->hitMany(['first', 'second'], 60);
        $limiter->hitMany(['first', 'second'], 60);

        self::assertSame(0, DB::table('cache')->count());
        self::assertSame(4, DB::table('tenant_cache')->where('key', 'like', 'tenant:42:%')->count());
        self::assertSame(2, $limiter->attempts('first'));
        self::assertSame(2, $limiter->attempts('second'));
    }

    public function test_warm_batch_write_failures_retry_without_losing_or_double_counting_hits(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hitMany(['first', 'second'], 60);
        $writes = 0;
        DB::connection()->beforeExecuting(static function (string $query) use (&$writes): void {
            if (str_starts_with($query, 'insert') && ++$writes === 1) {
                throw new PDOException('database is locked');
            }
        });

        $limiter->hitMany(['first', 'second'], 60);

        self::assertSame(2, $writes);
        self::assertSame(2, $limiter->attempts('first'));
        self::assertSame(2, $limiter->attempts('second'));
    }

    public function test_an_exception_discards_all_pending_warm_increments(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hitMany(['first', 'second'], 60);

        try {
            $limiter->batch(['first', 'second'], static function (LaravelRateLimiter $batch): void {
                $batch->hit('first', 60);
                $batch->hit('second', 60);
                throw new RuntimeException('Simulated callback failure');
            });
            self::fail('Expected the callback failure to propagate.');
        } catch (RuntimeException $exception) {
            self::assertSame('Simulated callback failure', $exception->getMessage());
        }

        self::assertSame(1, $limiter->attempts('first'));
        self::assertSame(1, $limiter->attempts('second'));
    }

    public function test_a_batch_does_not_reuse_a_snapshot_across_an_expiry_boundary(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('counter', 1);

        $limiter->batch(['counter'], function (LaravelRateLimiter $batch): void {
            $this->travel(2)->seconds();
            self::assertSame(0, $batch->attempts('counter'));
            self::assertSame(1, $batch->hit('counter', 60));
        });

        self::assertSame(60, $limiter->availableIn('counter'));
    }

    public function test_failed_batches_roll_back_all_counter_changes(): void
    {
        $limiter = app(RateLimiter::class);

        try {
            $limiter->batch(['first', 'second'], static function (LaravelRateLimiter $batch): void {
                $batch->hit('first', 60);
                $batch->hit('second', 60);
                throw new RuntimeException('Simulated write failure');
            });
            self::fail('Expected the write failure to propagate.');
        } catch (RuntimeException $exception) {
            self::assertSame('Simulated write failure', $exception->getMessage());
        }

        self::assertSame(0, $limiter->attempts('first'));
        self::assertSame(0, $limiter->attempts('second'));
        self::assertNull(cache()->get('first:timer'));
    }

    public function test_retried_transactions_rebuild_the_snapshot_without_double_counting(): void
    {
        $calls = 0;
        $limiter = app(RateLimiter::class);
        $limiter->batch(['counter'], static function (LaravelRateLimiter $batch) use (&$calls): void {
            $calls++;
            $batch->hit('counter', 60);
            if ($calls === 1) {
                throw new PDOException('database is locked');
            }
        });

        self::assertSame(2, $calls);
        self::assertSame(1, $limiter->attempts('counter'));
    }

    public function test_hit_many_records_both_error_counters_with_one_commit(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hitMany(['401', 'client_error'], 60);
        $commits = 0;
        Event::listen(TransactionCommitted::class, static function ($event) use (&$commits): void {
            if ($event->connection->transactionLevel() === 0) {
                $commits++;
            }
        });

        $limiter->hitMany(['401', 'client_error'], 60);

        self::assertSame(1, $commits);
        self::assertSame(2, $limiter->attempts('401'));
        self::assertSame(2, $limiter->attempts('client_error'));
    }

    public function test_non_database_stores_keep_laravel_counter_behavior(): void
    {
        config()->set('cache.default', 'array');
        $limiter = app(RateLimiter::class);
        $limiter->hitMany(['first', 'second'], 60);
        $limiter->hitMany(['first', 'second'], 60);

        self::assertTrue($limiter->tooManyAttempts('first', 2));
        $limiter->clear('first');
        self::assertFalse($limiter->tooManyAttempts('first', 2));
        self::assertSame(2, $limiter->attempts('second'));
    }
}

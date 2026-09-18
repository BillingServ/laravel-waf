<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
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
    }

    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('cache', static function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->text('value');
            $table->integer('expiration');
        });
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

        // One behavior read, one bucket/timer read, three locked counter reads.
        $selects = array_filter(DB::getQueryLog(), static fn (array $query): bool => str_starts_with($query['query'], 'select'));
        self::assertCount(5, $selects);
        self::assertSame(1, $commits);
        $this->get('/limited')->assertStatus(429)->assertHeader('Retry-After');
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
        self::assertCount(8, $selects);
        self::assertSame(2, $commits);
    }

    public function test_increment_uses_the_locked_value_instead_of_overwriting_with_the_snapshot(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('counter', 60);

        $limiter->batch(['counter'], static function (LaravelRateLimiter $batch) use ($limiter): void {
            // Interleave another writer after the batch's initial read.
            self::assertSame(2, $limiter->hit('counter', 60));
            self::assertSame(3, $batch->hit('counter', 60));
        });

        self::assertSame(3, $limiter->attempts('counter'));
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

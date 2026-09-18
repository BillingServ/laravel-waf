<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Cache\CacheManager;
use Illuminate\Cache\DatabaseStore;
use Illuminate\Cache\RateLimiter as LaravelRateLimiter;
use Illuminate\Cache\Repository;

final class RateLimiter
{
    public function __construct(private readonly CacheManager $cache)
    {
    }

    /**
     * @param array<int, string> $keys
     * @return array<string, mixed>
     */
    public function attemptsMany(array $keys): array
    {
        return $this->repository()->many($keys);
    }

    public function tooManyAttempts(string $key, int $maxAttempts): bool
    {
        return $this->limiter()->tooManyAttempts($key, $maxAttempts);
    }

    public function hit(string $key, int $decaySeconds = 60): int
    {
        return $this->limiter()->hit($key, $decaySeconds);
    }

    public function attempts(string $key): int
    {
        return (int) $this->limiter()->attempts($key);
    }

    public function availableIn(string $key): int
    {
        return $this->limiter()->availableIn($key);
    }

    public function clear(string $key): void
    {
        $this->limiter()->clear($key);
    }

    /** @param array<int, string> $keys */
    public function hitMany(array $keys, int $decaySeconds): void
    {
        $this->batch($keys, static function (LaravelRateLimiter $limiter) use ($keys, $decaySeconds): void {
            foreach ($keys as $key) {
                $limiter->hit($key, $decaySeconds);
            }
        });
    }

    /**
     * Keep callbacks free of external side effects: database deadlocks may retry.
     *
     * @template T
     * @param array<int, string> $keys
     * @param callable(LaravelRateLimiter): T $callback
     * @return T
     */
    public function batch(array $keys, callable $callback): mixed
    {
        $cache = $this->repository();
        $store = $cache->getStore();

        if (!$store instanceof DatabaseStore || $keys === []) {
            return $callback(new LaravelRateLimiter($cache));
        }

        return $store->getConnection()->transaction(
            static fn () => $callback(new DatabaseCounterBatch($cache, $keys)),
            3,
        );
    }

    private function limiter(): LaravelRateLimiter
    {
        return new LaravelRateLimiter($this->repository());
    }

    private function repository(): Repository
    {
        // Resolve at use time: tenant middleware may replace the cache driver
        // after service providers or long-lived WAF services have booted.
        return $this->cache->store(config('cache.limiter'));
    }
}

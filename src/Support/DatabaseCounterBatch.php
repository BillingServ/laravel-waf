<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Cache\DatabaseStore;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;

/** @internal Only used within one database transaction. */
final class DatabaseCounterBatch extends RateLimiter
{
    /** @var array<string, mixed> */
    private array $values;

    private int $sampledAt;

    private ?DatabaseCounterStore $lockedStore = null;

    /** @var array<string, array{value: int|null, expiration: int}> */
    private array $lockedValues = [];

    /** @var array<string, array{value: int, expiration: int}> */
    private array $pending = [];

    /** @var array<string, true> */
    private array $forgotten = [];

    /** @param array<int, string> $keys */
    public function __construct(Repository $cache, array $keys)
    {
        parent::__construct($cache);

        $keys = array_values(array_unique(array_map($this->cleanRateLimiterKey(...), $keys)));
        $this->sampledAt = $this->currentTime();
        $allKeys = array_values(array_unique(array_merge(
            $keys,
            array_map(static fn (string $key): string => $key.':timer', $keys),
        )));

        // Subclasses may change serialization or cache semantics.
        $store = $cache->getStore();
        if ($store::class === DatabaseStore::class) {
            $lockedStore = new DatabaseCounterStore($store);
            $lockedValues = $lockedStore->lockCounters($allKeys);
            if ($lockedValues !== null) {
                $this->lockedStore = $lockedStore;
                $this->lockedValues = $lockedValues;
                $this->values = array_map(static fn (array $row): ?int => $row['value'], $lockedValues);

                return;
            }
        }

        $this->values = $cache->many($allKeys);
    }

    public function tooManyAttempts($key, $maxAttempts): bool
    {
        $key = $this->cleanRateLimiterKey($key);
        if ($this->hasLockedCounter($key)) {
            if (($this->lockedValues[$key]['value'] ?? 0) >= $maxAttempts) {
                if ($this->lockedValues[$key.':timer']['value'] !== null) {
                    return true;
                }

                $this->resetAttempts($key);
            }

            return false;
        }

        return parent::tooManyAttempts($key, $maxAttempts);
    }

    public function availableIn($key): int
    {
        $key = $this->cleanRateLimiterKey($key);
        if ($this->hasLockedCounter($key)) {
            return max(0, ($this->lockedValues[$key.':timer']['value'] ?? 0) - $this->currentTime());
        }

        return parent::availableIn($key);
    }

    public function attempts($key): mixed
    {
        $key = $this->cleanRateLimiterKey($key);

        if ($this->hasLockedCounter($key)) {
            return $this->lockedValues[$key]['value'] ?? 0;
        }

        if ($this->sampledAt === $this->currentTime() && array_key_exists($key, $this->values)) {
            return $this->values[$key] ?? 0;
        }

        return parent::attempts($key);
    }

    public function increment($key, $decaySeconds = 60, $amount = 1): int
    {
        $key = $this->cleanRateLimiterKey($key);

        if ($this->hasLockedCounter($key) && is_int($amount) && is_int($decaySeconds) && $decaySeconds > 0) {
            $expiration = $this->availableAt($decaySeconds);
            $timer = $key.':timer';
            if ($this->lockedValues[$timer]['value'] === null) {
                $this->lockedValues[$timer] = ['value' => $expiration, 'expiration' => $expiration];
                $this->pending[$timer] = $this->lockedValues[$timer];
                unset($this->forgotten[$timer]);
            }

            // Laravel starts missing counters at zero and repairs an existing
            // zero counter's expiration on the first increment.
            if (($this->lockedValues[$key]['value'] ?? 0) === 0) {
                $this->lockedValues[$key] = ['value' => 0, 'expiration' => $expiration];
            }
            $this->lockedValues[$key]['value'] += $amount;
            $this->values[$key] = $this->lockedValues[$key]['value'];
            $this->pending[$key] = $this->lockedValues[$key];
            unset($this->forgotten[$key]);

            return $this->lockedValues[$key]['value'];
        }

        // Keep Laravel's behavior for unusual increment amounts or TTL inputs.
        $this->releaseSnapshot();

        // If the clock crossed an expiry boundary, let Laravel read fresh data.
        if ($this->sampledAt !== $this->currentTime() || !array_key_exists($key, $this->values)) {
            return parent::increment($key, $decaySeconds, $amount);
        }

        if (($this->values[$key.':timer'] ?? null) === null) {
            $this->cache->add($key.':timer', $this->availableAt($decaySeconds), $decaySeconds);
        }

        $added = $this->values[$key] === null && $this->cache->add($key, 0, $decaySeconds);

        // DatabaseStore still locks the row and increments the current value;
        // the prefetched value is never used to calculate or overwrite a count.
        $hits = (int) $this->cache->increment($key, $amount);
        if (!$added && $hits === $amount) {
            $this->cache->put($key, $amount, $decaySeconds);
        }

        $this->values[$key] = $hits;

        return $hits;
    }

    public function resetAttempts($key): bool
    {
        $key = $this->cleanRateLimiterKey($key);
        if ($this->hasLockedCounter($key)) {
            $this->forgetLocked($key);

            return true;
        }

        $this->releaseSnapshot();
        unset($this->values[$key]);

        return parent::resetAttempts($key);
    }

    public function clear($key): void
    {
        $key = $this->cleanRateLimiterKey($key);
        if ($this->hasLockedCounter($key)) {
            $this->forgetLocked($key);
            $this->forgetLocked($key.':timer');

            return;
        }

        parent::clear($key);
    }

    public function flush(): void
    {
        $this->lockedStore?->writeCounters($this->pending, array_keys($this->forgotten));
        $this->pending = [];
        $this->forgotten = [];
    }

    private function forgetLocked(string $key): void
    {
        $this->lockedValues[$key] = ['value' => null, 'expiration' => 0];
        $this->values[$key] = null;
        $this->forgotten[$key] = true;
        unset($this->pending[$key]);
    }

    private function hasLockedCounter(string $key): bool
    {
        if ($this->lockedStore === null) {
            return false;
        }

        if ($this->sampledAt === $this->currentTime()
            && isset($this->lockedValues[$key], $this->lockedValues[$key.':timer'])) {
            return true;
        }

        // Persist earlier increments before Laravel handles an expiry or a key
        // outside the batch. The enclosing transaction still owns all locks.
        $this->releaseSnapshot();

        return false;
    }

    private function releaseSnapshot(): void
    {
        if ($this->lockedStore !== null) {
            $this->flush();
            $this->lockedStore = null;
            $this->lockedValues = [];
            $this->values = [];
        }
    }
}

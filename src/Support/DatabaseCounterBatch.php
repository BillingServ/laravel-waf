<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;

/** @internal Only used within one database transaction. */
final class DatabaseCounterBatch extends RateLimiter
{
    /** @var array<string, mixed> */
    private array $values;

    private int $sampledAt;

    /** @param array<int, string> $keys */
    public function __construct(Repository $cache, array $keys)
    {
        parent::__construct($cache);

        $keys = array_map($this->cleanRateLimiterKey(...), $keys);
        $this->sampledAt = $this->currentTime();
        $this->values = $cache->many(array_merge(
            $keys,
            array_map(static fn (string $key): string => $key.':timer', $keys),
        ));
    }

    public function attempts($key): mixed
    {
        $key = $this->cleanRateLimiterKey($key);

        if ($this->sampledAt === $this->currentTime() && array_key_exists($key, $this->values)) {
            return $this->values[$key] ?? 0;
        }

        return parent::attempts($key);
    }

    public function increment($key, $decaySeconds = 60, $amount = 1): int
    {
        $key = $this->cleanRateLimiterKey($key);

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
        unset($this->values[$this->cleanRateLimiterKey($key)]);

        return parent::resetAttempts($key);
    }
}

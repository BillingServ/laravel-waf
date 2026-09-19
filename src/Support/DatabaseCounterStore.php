<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Cache\DatabaseStore;
use Illuminate\Database\SqlServerConnection;

/** @internal Access to Laravel's database cache format inside a counter transaction. */
final class DatabaseCounterStore extends DatabaseStore
{
    /** @var array<int, string> */
    private array $reservations = [];

    public function __construct(DatabaseStore $store)
    {
        parent::__construct($store->getConnection(), $store->table, $store->getPrefix());
    }

    /**
     * Lock before reading counts so another request cannot change them before flush.
     * Reserve missing rows before using their values, including on databases
     * whose row locks do not protect absent keys. A competing insert must be
     * read back under lock rather than overwritten with a fresh count.
     *
     * @param array<int, string> $keys
     * @return array<string, array{value: int|null, expiration: int}>|null
     */
    public function lockCounters(array $keys): ?array
    {
        $prefixedKeys = array_map(fn (string $key): string => $this->prefix.$key, $keys);
        sort($prefixedKeys);
        $read = fn () => $this->table()->whereIn('key', $prefixedKeys)->orderBy('key')->lockForUpdate()->get();
        $rows = $read();
        $missing = array_diff($prefixedKeys, $rows->pluck('key')->all());

        if ($missing !== []) {
            // Laravel does not support insertOrIgnore for SQL Server.
            if ($this->connection instanceof SqlServerConnection) {
                return null;
            }

            $this->table()->insertOrIgnore(array_map(fn (string $key): array => [
                'key' => $key,
                'value' => $this->serialize(0),
                'expiration' => 0,
            ], array_values($missing)));
            $rows = $read();
        }

        $values = [];
        $now = $this->currentTime();
        foreach ($rows as $row) {
            $key = substr($row->key, strlen($this->prefix));
            if ((int) $row->expiration === 0) {
                $this->reservations[] = $key;
            }
            if ($row->expiration <= $now) {
                $values[$key] = ['value' => null, 'expiration' => (int) $row->expiration];

                continue;
            }

            // Only native serialized integers are optimized. Leave other cache
            // values and any custom store serialization to the original store.
            $value = preg_match('/^i:-?\d+;$/D', $row->value) ? $this->unserialize($row->value) : null;
            if (!is_int($value)) {
                // Collect every reservation before returning to Laravel.
                $this->reservations = $rows->filter(static fn ($row): bool => (int) $row->expiration === 0)
                    ->map(fn ($row): string => substr($row->key, strlen($this->prefix)))->all();
                $this->writeCounters([]);

                return null;
            }

            $values[$key] = [
                'value' => $value,
                'expiration' => (int) $row->expiration,
            ];
        }

        return $values;
    }

    /**
     * @param array<string, array{value: int, expiration: int}> $values
     * @param array<int, string> $forgotten
     */
    public function writeCounters(array $values, array $forgotten = []): void
    {
        $rows = [];
        ksort($values);
        foreach ($values as $key => $value) {
            $rows[] = [
                'key' => $this->prefix.$key,
                'value' => $this->serialize($value['value']),
                'expiration' => $value['expiration'],
            ];
        }

        if ($rows !== []) {
            // Existing windows retain their expiry; only new/reset entries get
            // the expiration calculated when the callback actually hits them.
            $this->table()->upsert($rows, 'key', ['value', 'expiration']);
        }

        // Rejection may leave later buckets unused. Do not leak reservation
        // rows or start their windows just because they were in the batch.
        $unused = array_diff($this->reservations, array_keys($values));
        $deleted = array_values(array_unique(array_merge($unused, $forgotten)));
        if ($deleted !== []) {
            $this->table()->whereIn('key', array_map(fn (string $key): string => $this->prefix.$key, $deleted))->delete();
        }
        $this->reservations = [];
    }
}

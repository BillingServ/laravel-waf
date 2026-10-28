<?php

namespace BillingServ\LaravelWaf\Security\Signatures;

use BillingServ\LaravelWaf\Support\MetricsRecorder;
use Illuminate\Contracts\Cache\Repository;
use InvalidArgumentException;
use JsonException;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Loads operator-managed signature files at runtime, so a rule can be added
 * or changed on the server without a deployment. The file format and
 * validation are shared with the Go gate; `lwafd check-signatures` is the
 * reference validator.
 *
 * Statics avoid repeat work in persistent workers. Last-valid documents are
 * also retained in Laravel's cache so ordinary PHP-FPM requests can recover
 * them after a malformed edit or an unavailable configured root.
 */
final class SignatureLoader
{
    public const BUILTIN_PATH = __DIR__.'/../../../resources/rules/core.json';

    private const MAX_FILE_BYTES = 1048576;
    private const MAX_RULES = 1024;
    private const MAX_CONDITIONS = 16;
    private const MAX_VALUES = 256;
    private const MAX_VALUE_BYTES = 1024;
    private const MAX_TTL = 86400;
    private const DEFAULT_TTL = 3600;
    private const RULE_ID = '/^[a-z0-9][a-z0-9_.-]{0,31}$/D';
    private const HEADER_NAME = '/^[a-z0-9-]{1,64}$/D';
    private const FIXED_TARGETS = ['method', 'path', 'query', 'user_agent', 'body'];
    private const OPS = ['equals', 'prefix', 'suffix', 'contains', 'regex'];

    /** @var array<string, array> */
    private static array $files = [];
    private static ?SignatureSet $set = null;
    private static string $signature = '';
    private static float $checkedAt = 0.0;
    private static string $lastErrors = '';
    private static array $roots = [];
    private static array $snapshot = [];

    public function __construct(
        private readonly MetricsRecorder $metrics,
        private readonly LoggerInterface $logger,
        private readonly Repository $cache,
    ) {
    }

    public function current(): SignatureSet
    {
        $paths = $this->paths();
        $signature = implode("\n", $paths);
        // Zero re-checks timestamps on every request, which is useful while
        // writing rules; production should keep the default few seconds.
        $interval = max(0, (int) config('laravel-waf.signatures.reload_interval_seconds', 5));
        $now = microtime(true);

        if (self::$set !== null && self::$signature === $signature && $interval > 0 && $now - self::$checkedAt < $interval) {
            return self::$set;
        }

        try {
            if (self::$set === null || self::$signature !== $signature) {
                $this->restore($signature);
            }
            self::$set = $this->reload($paths);
            self::$checkedAt = $now;
            self::$signature = $signature;
        } catch (Throwable $exception) {
            throw new SignatureException('Signature rules are unavailable.', 0, $exception);
        }

        return self::$set;
    }

    private function restore(string $signature): void
    {
        $snapshot = $this->cache->get($this->cacheKey($signature), []);
        self::$files = [];
        self::$roots = is_array($snapshot['roots'] ?? null) ? $snapshot['roots'] : [];
        self::$snapshot = is_array($snapshot) ? $snapshot : [];
        foreach ((array) ($snapshot['files'] ?? []) as $file => $json) {
            if (!is_string($file) || !is_string($json) || strlen($json) > self::MAX_FILE_BYTES) {
                continue;
            }
            self::$files[$file] = ['mtime' => null, 'size' => null, 'valid' => true, 'json' => $json, 'error' => null] + self::parse($json);
        }
    }

    private function cacheKey(string $signature): string
    {
        return 'laravel-waf:signatures:v1:'.hash('sha256', $signature);
    }

    /**
     * Validates one document and returns its compiled rules and disable list.
     *
     * @return array{rules: array, disable: array<int, string>}
     *
     * @throws InvalidArgumentException
     */
    public static function parse(string $json): array
    {
        try {
            $document = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('invalid JSON: '.$exception->getMessage());
        }

        if (!is_array($document) || array_is_list($document) && $document !== []) {
            throw new InvalidArgumentException('the document must be a JSON object');
        }
        self::onlyKeys($document, ['version', 'disable', 'rules'], 'document');
        if (($document['version'] ?? null) !== 1) {
            throw new InvalidArgumentException('version must be 1');
        }

        $disable = self::list($document['disable'] ?? [], 'disable');
        foreach ($disable as $id) {
            if (!is_string($id) || preg_match(self::RULE_ID, $id) !== 1) {
                throw new InvalidArgumentException('disable: invalid rule id');
            }
        }

        $rules = self::list($document['rules'] ?? [], 'rules');
        if (count($rules) > self::MAX_RULES) {
            throw new InvalidArgumentException('a file may contain at most '.self::MAX_RULES.' rules');
        }

        $compiled = [];
        foreach ($rules as $index => $rule) {
            $id = is_array($rule) && is_string($rule['id'] ?? null) ? $rule['id'] : '';
            try {
                $result = self::compileRule($rule);
            } catch (InvalidArgumentException $exception) {
                throw new InvalidArgumentException("rule {$index} ({$id}): ".$exception->getMessage());
            }
            if ($result !== null) {
                $compiled[] = $result;
            }
        }

        return ['rules' => $compiled, 'disable' => array_values($disable)];
    }

    /** @return array<int, string> */
    private function paths(): array
    {
        $paths = [];
        if (config('laravel-waf.signatures.builtin', true)) {
            $paths[] = self::BUILTIN_PATH;
        }

        foreach ((array) config('laravel-waf.signatures.paths', []) as $path) {
            if (is_string($path) && trim($path) !== '') {
                $paths[] = trim($path);
            }
        }

        return $paths;
    }

    /** @param array<int, string> $paths */
    private function reload(array $paths): SignatureSet
    {
        $errors = [];
        $seen = [];
        $documents = [];
        $unavailable = false;

        foreach ($this->discover($paths, $errors) as $file) {
            $seen[$file] = true;
            clearstatcache(true, $file);
            $mtime = @filemtime($file);
            $size = @filesize($file);
            $cached = self::$files[$file] ?? null;

            if ($mtime === false || $size === false) {
                $errors[] = $file.': unreadable';
                if ($cached !== null && $cached['valid']) {
                    $documents[] = $cached;
                } else {
                    $unavailable = true;
                }

                continue;
            }

            $contents = null;
            try {
                if ($size > self::MAX_FILE_BYTES) {
                    throw new InvalidArgumentException('file exceeds '.self::MAX_FILE_BYTES.' bytes');
                }
                $contents = @file_get_contents($file, false, null, 0, self::MAX_FILE_BYTES + 1);
                if ($contents === false) {
                    throw new InvalidArgumentException('unreadable');
                }
                if (strlen($contents) > self::MAX_FILE_BYTES) {
                    throw new InvalidArgumentException('file exceeds '.self::MAX_FILE_BYTES.' bytes');
                }
                // Content comparison also sees same-size edits within one
                // filesystem timestamp tick. Bad versions keep their error.
                if ($cached !== null && ($cached['version'] ?? $cached['json'] ?? null) === $contents) {
                    if (($cached['error'] ?? null) !== null) {
                        $errors[] = $file.': '.$cached['error'];
                    }
                    if ($cached['valid']) {
                        $documents[] = $cached;
                    } else {
                        $unavailable = true;
                    }

                    continue;
                }

                $parsed = self::parse($contents);
                self::$files[$file] = ['mtime' => $mtime, 'size' => $size, 'valid' => true, 'json' => $contents, 'error' => null] + $parsed;
                $documents[] = self::$files[$file];
            } catch (InvalidArgumentException $exception) {
                $errors[] = $file.': '.$exception->getMessage();
                // Keep the last valid rules, but do not re-parse this version.
                self::$files[$file] = [
                    'mtime' => $mtime,
                    'size' => $size,
                    'rules' => $cached['rules'] ?? [],
                    'disable' => $cached['disable'] ?? [],
                    'valid' => $cached['valid'] ?? false,
                    'json' => $cached['json'] ?? null,
                    'version' => $contents ?? null,
                    'error' => $exception->getMessage(),
                ];
                if ($cached !== null && $cached['valid']) {
                    $documents[] = $cached;
                } else {
                    $unavailable = true;
                }
            }
        }

        self::$files = array_intersect_key(self::$files, $seen);
        $this->report($errors);
        if ($unavailable || ($errors !== [] && $documents === [])) {
            throw new SignatureException('No valid signature rules are available.');
        }

        $disabled = [];
        foreach ($documents as $document) {
            foreach ($document['disable'] as $id) {
                $disabled[$id] = true;
            }
        }

        $rules = [];
        foreach ($documents as $document) {
            foreach ($document['rules'] as $rule) {
                if (!isset($disabled[$rule['id']])) {
                    $rules[] = $rule;
                }
            }
        }

        if (count($rules) > self::MAX_RULES * 4) {
            throw new SignatureException('Too many active signature rules.');
        }
        $snapshot = ['roots' => self::$roots, 'files' => []];
        foreach (self::$files as $file => $cached) {
            if ($cached['valid']) {
                $snapshot['files'][$file] = $cached['json'];
            }
        }
        if ($snapshot !== self::$snapshot) {
            if (!$this->cache->forever($this->cacheKey(implode("\n", $paths)), $snapshot)) {
                throw new SignatureException('Unable to retain valid signature rules.');
            }
            self::$snapshot = $snapshot;
        }

        return new SignatureSet($rules);
    }

    /**
     * @param array<int, string> $paths
     * @param array<int, string> $errors
     *
     * @return array<int, string>
     */
    private function discover(array $paths, array &$errors): array
    {
        $files = [];
        foreach ($paths as $path) {
            clearstatcache(true, $path);
            if (is_dir($path)) {
                $entries = @scandir($path);
                if ($entries === false) {
                    $errors[] = $path.': unreadable directory';
                    array_push($files, ...(self::$roots[$path] ?? []));

                    continue;
                }
                $matches = array_map(
                    static fn (string $name): string => rtrim($path, '/').'/'.$name,
                    array_values(array_filter($entries, static fn (string $name): bool => str_ends_with($name, '.json'))),
                );
                sort($matches, SORT_STRING);
                self::$roots[$path] = $matches;
                array_push($files, ...$matches);
            } elseif (is_file($path) || str_ends_with($path, '.json')) {
                self::$roots[$path] = [$path];
                $files[] = $path;
            } elseif (array_key_exists($path, self::$roots) || file_exists($path)) {
                $errors[] = $path.': unavailable directory';
                array_push($files, ...(self::$roots[$path] ?? []));
            }
        }

        return $files;
    }

    /** @param array<int, string> $errors */
    private function report(array $errors): void
    {
        $current = implode('; ', $errors);
        if ($current !== '' && $current !== self::$lastErrors) {
            $this->metrics->error('signatures');
            try {
                $this->logger->warning('Laravel WAF signature reload kept the last valid rules.', [
                    'errors' => array_slice($errors, 0, 10),
                ]);
            } catch (Throwable) {
                $this->metrics->error('security_logging');
            }
        }

        self::$lastErrors = $current;
    }

    private static function compileRule(mixed $rule): ?array
    {
        if (!is_array($rule) || array_is_list($rule)) {
            throw new InvalidArgumentException('a rule must be an object');
        }
        self::onlyKeys($rule, ['id', 'description', 'action', 'ttl', 'enabled', 'conditions'], 'rule');

        $id = $rule['id'] ?? null;
        if (!is_string($id) || preg_match(self::RULE_ID, $id) !== 1) {
            throw new InvalidArgumentException('id must match '.self::RULE_ID);
        }
        if (isset($rule['description']) && !is_string($rule['description'])) {
            throw new InvalidArgumentException('description must be a string');
        }

        $action = $rule['action'] ?? 'block';
        if (!in_array($action, ['log', 'block', 'ban'], true)) {
            throw new InvalidArgumentException('action must be log, block, or ban');
        }

        $ttl = $rule['ttl'] ?? 0;
        if (!is_int($ttl)) {
            throw new InvalidArgumentException('ttl must be an integer');
        }
        $ttl = $ttl === 0 ? self::DEFAULT_TTL : $ttl;
        if ($ttl < 1 || $ttl > self::MAX_TTL) {
            throw new InvalidArgumentException('ttl must be between 1 and '.self::MAX_TTL.' seconds');
        }

        $enabled = $rule['enabled'] ?? true;
        if (!is_bool($enabled)) {
            throw new InvalidArgumentException('enabled must be a boolean');
        }

        $conditions = self::list($rule['conditions'] ?? [], 'conditions');
        if ($conditions === [] || count($conditions) > self::MAX_CONDITIONS) {
            throw new InvalidArgumentException('a rule needs between 1 and '.self::MAX_CONDITIONS.' conditions');
        }

        $compiled = [];
        foreach ($conditions as $index => $condition) {
            try {
                $compiled[] = self::compileCondition($condition);
            } catch (InvalidArgumentException $exception) {
                throw new InvalidArgumentException("condition {$index}: ".$exception->getMessage());
            }
        }

        // Validate fully before honouring enabled=false, as the gate does.
        if (!$enabled) {
            return null;
        }

        return ['id' => $id, 'action' => $action, 'ttl' => $ttl, 'conditions' => $compiled];
    }

    private static function compileCondition(mixed $condition): array
    {
        if (!is_array($condition) || array_is_list($condition)) {
            throw new InvalidArgumentException('a condition must be an object');
        }
        self::onlyKeys($condition, ['target', 'op', 'value', 'values', 'negate'], 'condition');

        $targets = $condition['target'] ?? null;
        $targets = is_string($targets) ? [$targets] : $targets;
        if (!is_array($targets) || $targets === [] || !array_is_list($targets)) {
            throw new InvalidArgumentException('target is required');
        }

        $normalizedTargets = [];
        foreach ($targets as $target) {
            if (!is_string($target)) {
                throw new InvalidArgumentException('target must be a string or a list of strings');
            }
            $target = strtolower(trim($target));
            $valid = str_starts_with($target, 'header:')
                ? preg_match(self::HEADER_NAME, substr($target, 7)) === 1
                : in_array($target, self::FIXED_TARGETS, true);
            if (!$valid) {
                throw new InvalidArgumentException("unknown target \"{$target}\"");
            }
            $normalizedTargets[] = $target;
        }

        $op = $condition['op'] ?? null;
        if (!in_array($op, self::OPS, true)) {
            throw new InvalidArgumentException('op must be equals, prefix, suffix, contains, or regex');
        }

        $negate = $condition['negate'] ?? false;
        if (!is_bool($negate)) {
            throw new InvalidArgumentException('negate must be a boolean');
        }

        $values = self::list($condition['values'] ?? [], 'values');
        if (array_key_exists('value', $condition) && $condition['value'] !== null) {
            $values[] = $condition['value'];
        }
        if ($values === [] || count($values) > self::MAX_VALUES) {
            throw new InvalidArgumentException('a condition needs between 1 and '.self::MAX_VALUES.' values');
        }
        foreach ($values as $value) {
            if (!is_string($value)) {
                throw new InvalidArgumentException('values must be strings');
            }
        }

        $compiled = ['targets' => $normalizedTargets, 'op' => $op, 'values' => [], 'pattern' => null, 'negate' => $negate];
        if ($op === 'regex') {
            if (count($values) !== 1) {
                throw new InvalidArgumentException('regex conditions take exactly one value');
            }
            $compiled['pattern'] = self::compileRegex($values[0]);

            return $compiled;
        }

        foreach ($values as $value) {
            if (strlen($value) > self::MAX_VALUE_BYTES || ($value === '' && $op !== 'equals')) {
                throw new InvalidArgumentException('values must be between 1 and '.self::MAX_VALUE_BYTES.' bytes');
            }
            $compiled['values'][] = strtolower($value);
        }

        return $compiled;
    }

    private static function compileRegex(string $pattern): string
    {
        if ($pattern === '' || strlen($pattern) > self::MAX_VALUE_BYTES) {
            throw new InvalidArgumentException('regex must be between 1 and '.self::MAX_VALUE_BYTES.' bytes');
        }

        // The gate uses Go's RE2 engine. Reject the common PCRE-only
        // constructs so a file valid here is not rejected by the agent.
        if (preg_match('/\(\?<?[=!]|\(\?>|\\\\[1-9]|\\\\k[<{\']|[*+?}][+]/', $pattern) === 1) {
            throw new InvalidArgumentException('regex must use RE2 syntax (no lookaround, backreferences, atomic groups, or possessive quantifiers)');
        }

        // No "u" modifier: invalid UTF-8 in an attack must not make the
        // match fail open. \x01 cannot appear in a sensible pattern.
        $compiled = "\x01".$pattern."\x01i";
        if (str_contains($pattern, "\x01") || @preg_match($compiled, '') === false) {
            throw new InvalidArgumentException('invalid regex');
        }

        return $compiled;
    }

    private static function list(mixed $value, string $name): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidArgumentException("{$name} must be a list");
        }

        return $value;
    }

    private static function onlyKeys(array $value, array $allowed, string $name): void
    {
        $unknown = array_diff(array_keys($value), $allowed);
        if ($unknown !== []) {
            throw new InvalidArgumentException("unknown {$name} field \"".reset($unknown).'"');
        }
    }

    /** Resets per-process state; intended for tests. */
    public static function flush(): void
    {
        self::$files = [];
        self::$set = null;
        self::$signature = '';
        self::$checkedAt = 0.0;
        self::$lastErrors = '';
        self::$roots = [];
        self::$snapshot = [];
    }
}

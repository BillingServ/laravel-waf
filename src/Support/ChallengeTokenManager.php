<?php

namespace BillingServ\LaravelWaf\Support;

use JsonException;

final class ChallengeTokenManager
{
    private const MAX_TOKEN_LENGTH = 4096;

    public function __construct(private readonly ?string $secret)
    {
    }

    public function issueRequest(string $ip, string $returnTo, int $ttlSeconds): ?string
    {
        $returnTo = $this->returnTo($returnTo);

        if ($returnTo === null) {
            return null;
        }

        return $this->issue([
            'kind' => 'request',
            'ip' => $ip,
            'return_to' => $returnTo,
        ], $ttlSeconds);
    }

    public function requestReturnTo(?string $token, string $ip): ?string
    {
        $payload = $this->read($token);

        if ($payload === null
            || ($payload['kind'] ?? null) !== 'request'
            || ($payload['ip'] ?? null) !== $ip
            || !is_string($payload['return_to'] ?? null)) {
            return null;
        }

        return $this->returnTo($payload['return_to']);
    }

    public function issuePass(string $ip, int $ttlSeconds): ?string
    {
        return $this->issue([
            'kind' => 'pass',
            'ip' => $ip,
        ], $ttlSeconds);
    }

    public function isPassed(?string $token, string $ip): bool
    {
        $payload = $this->read($token);

        return $payload !== null
            && ($payload['kind'] ?? null) === 'pass'
            && ($payload['ip'] ?? null) === $ip;
    }

    private function issue(array $payload, int $ttlSeconds): ?string
    {
        if ($this->secret === null || $this->secret === '') {
            return null;
        }

        try {
            $payload = array_merge($payload, [
                'version' => 1,
                'expires_at' => time() + max(1, min(86400, $ttlSeconds)),
                'nonce' => bin2hex(random_bytes(16)),
            ]);
            $encoded = $this->base64Url(json_encode(
                $payload,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
            ));
        } catch (\Throwable) {
            return null;
        }

        $token = $encoded.'.'.hash_hmac('sha256', $encoded, $this->secret);

        return strlen($token) <= self::MAX_TOKEN_LENGTH ? $token : null;
    }

    /** @return array<string, mixed>|null */
    private function read(?string $token): ?array
    {
        if ($this->secret === null || $this->secret === '' || !is_string($token) || $token === '' || strlen($token) > self::MAX_TOKEN_LENGTH) {
            return null;
        }

        $parts = explode('.', $token, 2);
        if (count($parts) !== 2 || !preg_match('/^[a-f0-9]{64}$/', $parts[1])) {
            return null;
        }

        $expected = hash_hmac('sha256', $parts[0], $this->secret);
        if (!hash_equals($expected, $parts[1])) {
            return null;
        }

        $encoded = strtr($parts[0], '-_', '+/');
        $padding = strlen($encoded) % 4;
        if ($padding !== 0) {
            $encoded .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($encoded, true);
        if (!is_string($decoded)) {
            return null;
        }

        try {
            $payload = json_decode($decoded, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($payload)
            || ($payload['version'] ?? null) !== 1
            || !is_string($payload['ip'] ?? null)
            || !is_int($payload['expires_at'] ?? null)
            || $payload['expires_at'] < time()) {
            return null;
        }

        return $payload;
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function returnTo(string $returnTo): ?string
    {
        if ($returnTo === '' || strlen($returnTo) > 2048 || str_contains($returnTo, "\r") || str_contains($returnTo, "\n") || str_contains($returnTo, '\\')) {
            return null;
        }

        if ($returnTo[0] !== '/' || str_starts_with($returnTo, '//')) {
            return null;
        }

        return $returnTo;
    }
}

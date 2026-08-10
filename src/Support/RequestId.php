<?php

namespace BillingServ\LaravelWaf\Support;

final class RequestId
{
    public static function make(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Throwable) {
            return substr(hash('sha256', (string) hrtime(true)), 0, 32);
        }
    }

    public static function normalize(?string $requestId): string
    {
        return is_string($requestId)
            && preg_match('/^[a-f0-9]{32}$/D', $requestId) === 1
                ? $requestId
                : self::make();
    }
}

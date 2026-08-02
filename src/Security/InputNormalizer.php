<?php

namespace BillingServ\LaravelWaf\Security;

final class InputNormalizer
{
    public static function normalize(string $value): string
    {
        $normalized = $value;

        for ($attempt = 0; $attempt < 2; $attempt++) {
            $decoded = rawurldecode($normalized);
            if ($decoded === $normalized) {
                break;
            }

            $normalized = $decoded;
        }

        $normalized = html_entity_decode($normalized, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return function_exists('mb_strtolower')
            ? mb_strtolower($normalized, 'UTF-8')
            : strtolower($normalized);
    }
}

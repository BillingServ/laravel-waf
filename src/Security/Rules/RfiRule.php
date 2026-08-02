<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class RfiRule extends PatternRule
{
    protected function category(): string
    {
        return 'rfi';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'dangerous_wrapper', 'pattern' => '~\b(?:php|data|file|gopher|expect|phar|zip):~iu'],
        ];
    }

    protected function matches(string $pattern, string $value, string $field): bool
    {
        if (parent::matches($pattern, $value, $field)) {
            return true;
        }

        if (preg_match('~https?://~iu', $value) !== 1) {
            return false;
        }

        $fields = $this->config('remote_url_fields', []);
        if (!is_array($fields) || ! $this->fieldMatches($field, $fields)) {
            return false;
        }

        $host = parse_url($value, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return false;
        }

        $allowed = $this->config('allowed_remote_hosts', []);
        if (!is_array($allowed) || $allowed === []) {
            return true;
        }

        foreach ($allowed as $allowedHost) {
            if (is_string($allowedHost) && strcasecmp($host, trim($allowedHost)) === 0) {
                return false;
            }
        }

        return true;
    }

    private function fieldMatches(string $field, array $fields): bool
    {
        foreach ($fields as $candidate) {
            if (is_string($candidate) && str_contains(strtolower($field), strtolower(trim($candidate)))) {
                return true;
            }
        }

        return false;
    }
}

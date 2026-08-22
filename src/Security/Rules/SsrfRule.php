<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Security\InputNormalizer;
use BillingServ\LaravelWaf\Support\UrlSafety;

final class SsrfRule extends PatternRule
{
    protected function category(): string
    {
        return 'ssrf';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'unsafe_scheme', 'pattern' => '~\b(?:file|gopher|dict|ftp|sftp|ldap|ldaps|data|phar|expect):~iu'],
        ];
    }

    protected function matches(string $pattern, string $value, string $field): bool
    {
        if (parent::matches($pattern, $value, $field)) {
            return true;
        }

        $normalized = InputNormalizer::normalize($value);
        $fields = $this->config('url_fields', []);
        $isUrlField = $this->fieldMatches($field, is_array($fields) ? $fields : []);
        $hasScheme = preg_match('~^[A-Za-z][A-Za-z0-9+.-]*://|^//~', $normalized) === 1;
        if (!$isUrlField && !$hasScheme) {
            return false;
        }

        $parts = UrlSafety::parse($normalized, $isUrlField);
        if ($parts === null) {
            return $isUrlField;
        }

        $allowed = UrlSafety::isAllowedHost($parts['host'], $this->config('allowed_hosts', []));
        if ($allowed) {
            return false;
        }

        if (!(bool) $this->config('allow_private_ips', false) && UrlSafety::isPrivateHost($parts['host'])) {
            return true;
        }

        $allowedHosts = $this->config('allowed_hosts', []);

        return is_array($allowedHosts) && $allowedHosts !== [];
    }

    /** @param array<int, mixed> $fields */
    private function fieldMatches(string $field, array $fields): bool
    {
        $field = strtolower($field);

        foreach ($fields as $candidate) {
            if (!is_string($candidate)) {
                continue;
            }

            $candidate = strtolower(trim($candidate));
            if ($candidate !== ''
                && preg_match('~(?:^|[._:-])'.preg_quote($candidate, '~').'(?=$|[._:-])~', $field) === 1) {
                return true;
            }
        }

        return false;
    }
}

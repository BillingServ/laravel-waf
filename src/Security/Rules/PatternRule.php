<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\InputNormalizer;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Support\RequestContext;
use Illuminate\Http\Request;

abstract class PatternRule implements InspectionRule
{
    public function __construct(
        protected readonly RequestInputCollector $inputs,
        protected readonly array $configuration = [],
    ) {
    }

    public function inspect(Request $request): ?Finding
    {
        foreach ($this->inputs->collect($request) as $input) {
            if ($this->excluded($input->field)) {
                continue;
            }

            $value = InputNormalizer::normalize($input->value);
            foreach ($this->patterns() as $pattern) {
                if ($this->matches($pattern['pattern'], $value, $input->field)) {
                    return new Finding(
                        $this->category(),
                        $pattern['id'],
                        $pattern['confidence'] ?? 'high',
                        $input->source,
                        $this->field($input->field),
                        $request->ip() ?: 'unknown',
                        RequestContext::routeLabel($request),
                        RequestContext::method($request),
                    );
                }
            }
        }

        return null;
    }

    abstract protected function category(): string;

    /** @return array<int, array{id: string, pattern: string, confidence?: string}> */
    abstract protected function patterns(): array;

    protected function matches(string $pattern, string $value, string $field): bool
    {
        return preg_match($pattern, $value) === 1;
    }

    protected function config(string $key, mixed $default = null): mixed
    {
        return $this->configuration[$key] ?? $default;
    }

    private function excluded(string $field): bool
    {
        $excluded = $this->config('exclude_fields', []);
        if (!is_array($excluded)) {
            return false;
        }

        foreach ($excluded as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            $quoted = preg_quote(strtolower($pattern), '~');
            $quoted = str_replace('\\*', '.*', $quoted);
            if (preg_match('~^'.$quoted.'$~i', $field) === 1) {
                return true;
            }
        }

        return false;
    }

    private function field(string $field): ?string
    {
        $field = preg_replace('/[^A-Za-z0-9_.:-]/', '_', $field) ?: 'value';

        return substr($field, 0, 128);
    }
}

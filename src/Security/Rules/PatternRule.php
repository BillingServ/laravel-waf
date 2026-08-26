<?php

namespace BillingServ\LaravelWaf\Security\Rules;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Support\RequestContext;
use Illuminate\Http\Request;

abstract class PatternRule implements InspectionRule
{
    /** @var array<int, string>|null */
    private ?array $exclusionExpressions = null;

    public function __construct(
        protected readonly RequestInputCollector $inputs,
        protected readonly array $configuration = [],
    ) {
    }

    public function inspect(Request $request): ?Finding
    {
        // Patterns and exclusions are resolved once per request, not once per
        // input value; the collector already normalized every value.
        $patterns = $this->patterns();
        foreach ($this->inputs->collect($request) as $input) {
            if ($this->excluded($input->field)) {
                continue;
            }

            foreach ($patterns as $pattern) {
                if ($this->matches($pattern['pattern'], $input->value, $input->field)) {
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
        if ($this->exclusionExpressions === null) {
            $this->exclusionExpressions = [];

            foreach ((array) $this->config('exclude_fields', []) as $pattern) {
                if (is_string($pattern) && $pattern !== '') {
                    $quoted = str_replace('\\*', '.*', preg_quote(strtolower($pattern), '~'));
                    $this->exclusionExpressions[] = '~^'.$quoted.'$~i';
                }
            }
        }

        $field = strtolower($field);
        foreach ($this->exclusionExpressions as $expression) {
            if (preg_match($expression, $field) === 1) {
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

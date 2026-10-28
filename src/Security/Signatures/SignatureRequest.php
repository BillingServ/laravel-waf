<?php

namespace BillingServ\LaravelWaf\Security\Signatures;

use BillingServ\LaravelWaf\Security\RequestInputCollector;
use Illuminate\Http\Request;

/**
 * The normalized request view that signatures match against. Path, query,
 * method, and header normalization must stay byte-for-byte identical to the
 * Go gate so one rule file behaves the same before and inside PHP.
 */
final class SignatureRequest
{
    private const MAX_INSPECTED_BYTES = 8192;

    /** @var array<string, array<int, string>> */
    private array $resolved = [];

    public function __construct(
        private readonly Request $request,
        private readonly RequestInputCollector $inputs,
        private readonly bool $rememberInputs = true,
    ) {
    }

    /** @return array<int, string> */
    public function values(string $target): array
    {
        return $this->resolved[$target] ??= $this->resolve($target);
    }

    /** @return array<int, string> */
    private function resolve(string $target): array
    {
        if ($target === 'path' || $target === 'query') {
            [$path, $query] = array_pad(explode('?', $this->uri(), 2), 2, '');

            return [$target === 'path' ? self::normalizePath($path) : self::normalizeQuery($query)];
        }

        if ($target === 'method') {
            // The real method, not a _method override, matches what Nginx saw.
            return [strtolower($this->request->getRealMethod())];
        }

        if ($target === 'user_agent') {
            return [$this->header('user-agent')];
        }

        if (str_starts_with($target, 'header:')) {
            return [$this->header(substr($target, 7))];
        }

        if ($target === 'body') {
            $values = [];
            $inputs = $this->inputs->collect($this->request, $this->rememberInputs);
            if ($this->request->attributes->get('laravel-waf.input_truncated') === true) {
                throw new SignatureException('Signature body exceeds inspection limits.');
            }
            foreach ($inputs as $input) {
                if ($input->source === 'body') {
                    $values[] = $input->value;
                }
            }

            return $values;
        }

        return [];
    }

    private function uri(): string
    {
        return substr($this->request->getRequestUri(), 0, self::MAX_INSPECTED_BYTES);
    }

    private function header(string $name): string
    {
        $value = implode(', ', array_filter(
            $this->request->headers->all(strtolower($name)),
            'is_string',
        ));

        return strtolower(substr($value, 0, self::MAX_INSPECTED_BYTES));
    }

    public static function normalizePath(string $path): string
    {
        return strtolower(self::decode($path, static fn (string $value): string => rawurldecode($value)));
    }

    public static function normalizeQuery(string $query): string
    {
        return strtolower(self::decode($query, static fn (string $value): string => urldecode($value)));
    }

    private static function decode(string $value, callable $decoder): string
    {
        for ($pass = 0; $pass < 2; $pass++) {
            $decoded = $decoder($value);
            if ($decoded === $value) {
                break;
            }

            $value = $decoded;
        }

        return $value;
    }
}

<?php

namespace BillingServ\LaravelWaf\Security\Signatures;

/**
 * An ordered list of compiled signatures. Matching mirrors the Go gate
 * (agent/internal/signatures): every condition of a rule must match, the
 * first blocking rule wins, and log-only rules never stop evaluation.
 */
final class SignatureSet
{
    /**
     * @param array<int, array{
     *     id: string,
     *     action: string,
     *     ttl: int,
     *     conditions: array<int, array{targets: array<int, string>, op: string, values: array<int, string>, pattern: ?string, negate: bool}>
     * }> $rules
     */
    public function __construct(public readonly array $rules = [])
    {
    }

    /** @return array{0: ?array, 1: array<int, array>} the blocking rule and any log-only matches */
    public function match(SignatureRequest $request): array
    {
        $logged = [];
        foreach ($this->rules as $rule) {
            try {
                $matched = $this->matches($rule, $request);
            } catch (SignatureException $exception) {
                if ($rule['action'] !== 'log') {
                    throw $exception;
                }
                // An indeterminate log-only rule can record an observation,
                // but must not gain authority to reject the request.
                $logged[] = $rule;

                continue;
            }
            if (!$matched) {
                continue;
            }

            if ($rule['action'] === 'log') {
                $logged[] = $rule;

                continue;
            }

            return [$rule, $logged];
        }

        return [null, $logged];
    }

    private function matches(array $rule, SignatureRequest $request): bool
    {
        foreach ($rule['conditions'] as $condition) {
            if ($this->conditionMatches($condition, $request) === $condition['negate']) {
                return false;
            }
        }

        return true;
    }

    private function conditionMatches(array $condition, SignatureRequest $request): bool
    {
        foreach ($condition['targets'] as $target) {
            foreach ($request->values($target) as $value) {
                if ($condition['pattern'] !== null) {
                    $matched = preg_match($condition['pattern'], $value);
                    if ($matched === false) {
                        throw new SignatureException('Signature regex evaluation failed: '.preg_last_error_msg());
                    }
                    if ($matched === 1) {
                        return true;
                    }

                    continue;
                }

                foreach ($condition['values'] as $expected) {
                    if (match ($condition['op']) {
                        'equals' => $value === $expected,
                        'prefix' => str_starts_with($value, $expected),
                        'suffix' => str_ends_with($value, $expected),
                        'contains' => str_contains($value, $expected),
                        default => false,
                    }) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}

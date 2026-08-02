<?php

namespace BillingServ\LaravelWaf\Security;

use BillingServ\LaravelWaf\Contracts\InspectionRule;
use Illuminate\Http\Request;

final class RequestRuleEngine
{
    /** @param iterable<InspectionRule> $rules */
    public function __construct(private readonly iterable $rules)
    {
    }

    /** @return array<int, Finding> */
    public function inspect(Request $request): array
    {
        $maxFindings = max(1, min(32, (int) config('laravel-waf.rules.max_findings', 3)));
        $findings = [];

        foreach ($this->rules as $rule) {
            $finding = $rule->inspect($request);
            if ($finding === null) {
                continue;
            }

            $findings[] = $finding;
            if (count($findings) >= $maxFindings) {
                break;
            }
        }

        return $findings;
    }
}

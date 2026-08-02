<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class SqlInjectionRule extends PatternRule
{
    protected function category(): string
    {
        return 'sqli';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'tautology', 'pattern' => '~(?:[\'\"]\s*)?(?:or|and)\s+(?:[\'\"]?\s*)?\d+\s*=\s*\d+~iu'],
            ['id' => 'union_select', 'pattern' => '~\bunion\s+(?:all\s+)?select\b~iu'],
            ['id' => 'stacked_query', 'pattern' => '~;\s*(?:select|insert|update|delete|drop|alter|create|exec(?:ute)?)\b~iu'],
            ['id' => 'time_delay', 'pattern' => '~\b(?:sleep|benchmark|pg_sleep)\s*\(~iu'],
            ['id' => 'database_probe', 'pattern' => '~\b(?:information_schema|xp_cmdshell|load_file)\b~iu'],
            ['id' => 'sql_comment', 'pattern' => '~(?:--(?:\s|$)|/\*|\*/)~u'],
        ];
    }
}

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
            ['id' => 'tautology_string', 'pattern' => '~[\'"][a-z0-9_]{1,16}[\'"]\s*=\s*[\'"][a-z0-9_]{1,16}[\'"]~iu'],
            ['id' => 'boolean_true', 'pattern' => '~\b(?:or|and)\s+(?:true|1)\b\s*(?:--|#|;|$)~iu'],
            ['id' => 'union_select', 'pattern' => '~\bunion\s+(?:all\s+)?select\b~iu'],
            ['id' => 'stacked_query', 'pattern' => '~;\s*(?:select|insert|update|delete|drop|alter|create|exec(?:ute)?)\b~iu'],
            ['id' => 'time_delay', 'pattern' => '~\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay\b~iu'],
            ['id' => 'error_based', 'pattern' => '~\b(?:extractvalue|updatexml|xmlquery|dbms_utility)\s*\(~iu'],
            ['id' => 'database_probe', 'pattern' => '~\b(?:information_schema|xp_cmdshell|load_file)\b|@@(?:version|datadir|hostname)\b~iu'],
            ['id' => 'encoding_function', 'pattern' => '~\b(?:unhex|char|ascii|ord|hex)\s*\(\s*(?:0x|[\'"])~iu'],
            ['id' => 'sql_comment', 'pattern' => '~(?:--(?:\s|$)|/\*|\*/)~u'],
        ];
    }
}

<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class LdapInjectionRule extends PatternRule
{
    protected function category(): string
    {
        return 'ldap';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'filter_wildcard', 'pattern' => '~\([A-Za-z][A-Za-z0-9._-]{0,64}=\*[^)]*\)~u'],
            ['id' => 'filter_operator', 'pattern' => '~\(\s*[|&!]\s*\(|\)\s*\(|\)\s*\*~u'],
        ];
    }
}

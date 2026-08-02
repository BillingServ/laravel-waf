<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class NoSqlInjectionRule extends PatternRule
{
    protected function category(): string
    {
        return 'nosqli';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'operator_value', 'pattern' => '~(?:^|[\{\[,\s])(?:["\']?\$)(?:where|ne|nin|gt|gte|lt|lte|regex|exists|elemMatch)\b~iu'],
            ['id' => 'where_expression', 'pattern' => '~\$where\s*[:=]~iu'],
        ];
    }

    protected function matches(string $pattern, string $value, string $field): bool
    {
        if (preg_match('~(?:^|[._\[])\$?(?:where|ne|nin|gt|gte|lt|lte|regex|exists|elemMatch)(?:$|[.\]])~iu', $field) === 1) {
            return true;
        }

        return parent::matches($pattern, $value, $field);
    }
}

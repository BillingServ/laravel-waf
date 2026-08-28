<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class CrLfRule extends PatternRule
{
    protected function category(): string
    {
        return 'http';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'header_line_break', 'pattern' => "/(?:\r\n|\r|\n)(?:[ \t]*(?:[!#\$%&'*+\-.^_`|~0-9A-Za-z]+[ \t]*:|(?:\r\n|\r|\n)))/u"],
        ];
    }
}

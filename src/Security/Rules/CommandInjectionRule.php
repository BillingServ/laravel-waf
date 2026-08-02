<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class CommandInjectionRule extends PatternRule
{
    protected function category(): string
    {
        return 'command';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'command_substitution', 'pattern' => '~(?:\$\([^\r\n]{1,128}\)|`[^`\r\n]{1,128}`)~u'],
            ['id' => 'shell_operator', 'pattern' => '~[;&|]\s*(?:bash|sh|zsh|cmd|powershell|pwsh|curl|wget|nc|ncat|socat|whoami|id)\b~iu'],
            ['id' => 'process_function', 'pattern' => '~\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(~iu'],
        ];
    }
}

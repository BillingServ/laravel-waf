<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class LfiRule extends PatternRule
{
    protected function category(): string
    {
        return 'lfi';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'path_traversal', 'pattern' => '~(?:^|[\\/])\.\.(?:[\\/]|$)~iu'],
            ['id' => 'null_byte', 'pattern' => '~\x00~u'],
            ['id' => 'sensitive_file', 'pattern' => '~(?:/etc/(?:passwd|shadow|hosts)|/proc/self/(?:environ|cmdline)|(?:^|[\\/])(?:win|boot)\.ini)~iu'],
            ['id' => 'file_wrapper', 'pattern' => '~\b(?:php|file|zip|phar):~iu'],
        ];
    }
}

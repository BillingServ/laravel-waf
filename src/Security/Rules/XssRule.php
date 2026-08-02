<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class XssRule extends PatternRule
{
    protected function category(): string
    {
        return 'xss';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'script_tag', 'pattern' => '~<\s*/?\s*script\b~iu'],
            ['id' => 'event_handler', 'pattern' => '~\bon(?:error|load|click|mouseover|focus|animationstart|submit|change)\s*=~iu'],
            ['id' => 'javascript_scheme', 'pattern' => '~(?:java|vb)script\s*:~iu'],
            ['id' => 'html_data_scheme', 'pattern' => '~data\s*:\s*text/html~iu'],
            ['id' => 'dangerous_element', 'pattern' => '~<\s*/?\s*(?:iframe|object|embed|svg|style|base)\b~iu'],
        ];
    }
}

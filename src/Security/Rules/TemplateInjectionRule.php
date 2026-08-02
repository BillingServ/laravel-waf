<?php

namespace BillingServ\LaravelWaf\Security\Rules;

final class TemplateInjectionRule extends PatternRule
{
    protected function category(): string
    {
        return 'template';
    }

    protected function patterns(): array
    {
        return [
            ['id' => 'expression_template', 'pattern' => '~\{\{[^{}\r\n]{0,128}(?:\*|\+|__|config|request|self|class)[^{}\r\n]{0,128}\}\}~iu'],
            ['id' => 'expression_language', 'pattern' => '~\$\{[^{}\r\n]{0,128}(?:jndi:|7\s*[+*]\s*7|class|env|system|runtime)[^{}\r\n]{0,128}\}~iu'],
            ['id' => 'template_statement', 'pattern' => '~\{%[^%\r\n]{0,128}(?:for|if|include|extends|import|set)[^%\r\n]{0,128}%\}~iu'],
            ['id' => 'object_traversal', 'pattern' => '~(?:__class__|__mro__|__subclasses__|__globals__|constructor\s*[\[.])~iu'],
        ];
    }
}

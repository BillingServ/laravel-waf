<?php

namespace BillingServ\LaravelWaf\Security;

final readonly class Finding
{
    public function __construct(
        public string $category,
        public string $rule,
        public string $confidence,
        public string $source,
        public ?string $field,
        public string $ip,
        public string $route,
        public string $method,
        // A rule that carries its own decision (signatures) sets these;
        // null defers to the category/global action configuration.
        public ?string $action = null,
        public int $banTtlSeconds = 0,
    ) {
    }

    public function fingerprint(): string
    {
        return hash('sha256', implode('|', [
            $this->category,
            $this->rule,
            $this->ip,
            $this->route,
        ]));
    }

    /** @return array<string, string|null> */
    public function context(): array
    {
        return [
            'category' => $this->category,
            'rule' => $this->rule,
            'confidence' => $this->confidence,
            'source' => $this->source,
            'field' => $this->field,
            'ip' => $this->ip,
            'route' => $this->route,
            'method' => $this->method,
        ];
    }
}

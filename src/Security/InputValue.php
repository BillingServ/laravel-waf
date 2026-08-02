<?php

namespace BillingServ\LaravelWaf\Security;

final readonly class InputValue
{
    public function __construct(
        public string $source,
        public string $field,
        public string $value,
    ) {
    }
}

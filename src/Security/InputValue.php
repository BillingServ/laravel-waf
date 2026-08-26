<?php

namespace BillingServ\LaravelWaf\Security;

final readonly class InputValue
{
    /**
     * @param string $value the client value, truncated to the byte cap and
     *                      already URL/HTML-decoded and lower-cased
     */
    public function __construct(
        public string $source,
        public string $field,
        public string $value,
    ) {
    }
}

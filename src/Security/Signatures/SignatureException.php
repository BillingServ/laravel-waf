<?php

namespace BillingServ\LaravelWaf\Security\Signatures;

use RuntimeException;

/** A signature could not be evaluated safely; never treat this as a non-match. */
final class SignatureException extends RuntimeException
{
}

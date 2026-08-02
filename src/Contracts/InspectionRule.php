<?php

namespace BillingServ\LaravelWaf\Contracts;

use BillingServ\LaravelWaf\Security\Finding;
use Illuminate\Http\Request;

interface InspectionRule
{
    public function inspect(Request $request): ?Finding;
}

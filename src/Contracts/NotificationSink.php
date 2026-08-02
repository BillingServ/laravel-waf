<?php

namespace BillingServ\LaravelWaf\Contracts;

use BillingServ\LaravelWaf\Security\Finding;

interface NotificationSink
{
    public function notify(Finding $finding): void;
}

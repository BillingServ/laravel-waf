<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Security\Finding;

final class NullNotificationSink implements NotificationSink
{
    public function notify(Finding $finding): void
    {
        // Notifications are deliberately optional and must never affect requests.
    }
}

# Notifications

Notifications are disabled by default. Enable one or both built-in channels:

```dotenv
LARAVEL_WAF_NOTIFICATIONS_ENABLED=true
LARAVEL_WAF_NOTIFICATION_CHANNELS=email,slack
LARAVEL_WAF_NOTIFICATION_EMAIL_TO=security@example.com
LARAVEL_WAF_NOTIFICATION_SLACK_WEBHOOK=https://hooks.slack.com/services/...
LARAVEL_WAF_NOTIFICATION_COOLDOWN=300
```

Email uses the application's configured Laravel mailer. Slack uses the Laravel
HTTP client and accepts HTTPS webhook URLs only. Delivery is bounded by the
configured timeout; a delivery failure is logged and never changes the
protected request response. The cache cooldown prevents repeated notifications
for the same category, rule, IP, and route.

Notifications contain only the finding category, rule identifier, confidence,
source, field name, IP, route, and method. Raw query strings, request bodies,
headers, cookies, credentials, and payloads are intentionally excluded.

For queued or organization-specific delivery, bind
`BillingServ\LaravelWaf\Contracts\NotificationSink` in the application and
send the supplied `Finding` through the application's queue or notification
system. A custom sink should preserve the same redaction boundary.

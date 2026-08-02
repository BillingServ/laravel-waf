<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Security\Finding;
use Illuminate\Contracts\Container\Container;
use RuntimeException;

final class LaravelNotificationSink implements NotificationSink
{
    public function __construct(private readonly Container $container)
    {
    }

    public function notify(Finding $finding): void
    {
        $message = $this->message($finding);
        $channels = config('laravel-waf.notifications.channels', []);
        if (!is_array($channels)) {
            return;
        }

        foreach ($channels as $channel) {
            if ($channel === 'email') {
                $this->email($message);
            } elseif ($channel === 'slack') {
                $this->slack($message);
            }
        }
    }

    private function email(string $message): void
    {
        $recipients = config('laravel-waf.notifications.email.to', []);
        if (!is_array($recipients) || $recipients === []) {
            return;
        }

        if (!$this->container->bound('mailer')) {
            throw new RuntimeException('Laravel mailer is not available.');
        }

        $subject = (string) config('laravel-waf.notifications.email.subject', 'Laravel WAF security event');
        $mailer = $this->container->make('mailer');
        foreach ($recipients as $recipient) {
            if (!is_string($recipient) || filter_var($recipient, FILTER_VALIDATE_EMAIL) === false) {
                continue;
            }

            $mailer->raw($message, static function (mixed $mail) use ($recipient, $subject): void {
                $mail->to($recipient)->subject($subject);
            });
        }
    }

    private function slack(string $message): void
    {
        $url = config('laravel-waf.notifications.slack.webhook_url');
        if (!is_string($url) || !$this->safeWebhook($url)) {
            return;
        }

        $factoryClass = 'Illuminate\\Http\\Client\\Factory';
        if (!class_exists($factoryClass)) {
            throw new RuntimeException('Laravel HTTP client is not available.');
        }

        $timeout = max(1, min(10, (int) config('laravel-waf.notifications.timeout_seconds', 3)));
        $client = $this->container->bound($factoryClass)
            ? $this->container->make($factoryClass)
            : new $factoryClass();
        $request = $client->timeout($timeout);
        if (method_exists($request, 'withoutRedirecting')) {
            $request = $request->withoutRedirecting();
        }
        $response = $request->post($url, ['text' => $message]);

        if (method_exists($response, 'successful') && !$response->successful()) {
            throw new RuntimeException('Slack webhook returned an unsuccessful response.');
        }
    }

    private function safeWebhook(string $url): bool
    {
        if (strlen($url) > 2048 || preg_match('/[\r\n]/', $url) === 1) {
            return false;
        }

        $parts = parse_url($url);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null)
            && ($parts['user'] ?? null) === null
            && ($parts['pass'] ?? null) === null;
    }

    private function message(Finding $finding): string
    {
        $context = $finding->context();

        return implode("\n", [
            'Laravel WAF detected a security event.',
            'Category: '.($context['category'] ?? 'unknown'),
            'Rule: '.($context['rule'] ?? 'unknown'),
            'Confidence: '.($context['confidence'] ?? 'unknown'),
            'Source: '.($context['source'] ?? 'unknown'),
            'Field: '.($context['field'] ?? 'unknown'),
            'IP: '.($context['ip'] ?? 'unknown'),
            'Route: '.($context['route'] ?? 'unknown'),
            'Method: '.($context['method'] ?? 'unknown'),
        ]);
    }
}

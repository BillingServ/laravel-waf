<?php

namespace BillingServ\LaravelWaf\Security;

use BillingServ\LaravelWaf\Support\AgentBlocker;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\RequestContext;
use BillingServ\LaravelWaf\Support\SecurityNotifier;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Cache\RateLimiter;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Throwable;

final class LoginProtectionSubscriber
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly AgentBlocker $agentBlocker,
        private readonly MetricsRecorder $metrics,
        private readonly SecurityNotifier $notifier,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function subscribe(Dispatcher $events): void
    {
        $events->listen(Failed::class, [self::class, 'failed']);
        $events->listen(Lockout::class, [self::class, 'lockout']);
        $events->listen(Login::class, [self::class, 'login']);
    }

    public function failed(Failed $event): void
    {
        if (!$this->enabled() || !$this->guardAllowed($event->guard)) {
            return;
        }

        $request = $this->request();
        if ($request === null) {
            return;
        }

        $ip = $request->ip() ?: 'unknown';
        $identifier = $this->identifier($request, $event->credentials);
        $route = RequestContext::routeLabel($request);
        $finding = $this->finding($request, 'failed_login', 'auth');

        try {
            $decay = max(1, (int) config('laravel-waf.login.decay_seconds', 300));
            $this->limiter->hit(RateLimitKey::login($ip, $identifier), $decay);
            $ipKey = RateLimitKey::login($ip);
            $this->limiter->hit($ipKey, $decay);
            $attempts = $this->limiter->attempts($ipKey);

            $this->metrics->finding($finding, 'observe');
            $this->notifier->notify($finding);

            if ($attempts >= max(1, (int) config('laravel-waf.login.block_after_attempts', 10))
                && config('laravel-waf.login.auto_block', false)) {
                $this->agentBlocker->block(
                    $ip,
                    (int) config('laravel-waf.login.block_ttl_seconds', 900),
                    'login_failure',
                    'login',
                );
            }
        } catch (Throwable $exception) {
            $this->metrics->error('login_failure_handler');
            $this->warning('Laravel WAF login failure handler failed.', [
                'exception' => $exception::class,
                'route' => $route,
            ]);
        }
    }

    public function lockout(Lockout $event): void
    {
        if (!$this->enabled()) {
            return;
        }

        $request = $this->request();
        if ($request === null) {
            return;
        }

        $finding = $this->finding($request, 'login_lockout', 'auth');
        $this->metrics->finding($finding, 'observe');
        $this->notifier->notify($finding);

        if (config('laravel-waf.login.auto_block', false)) {
            $this->agentBlocker->block(
                $finding->ip,
                (int) config('laravel-waf.login.block_ttl_seconds', 900),
                'login_failure',
                'login',
            );
        }
    }

    public function login(Login $event): void
    {
        if (!$this->enabled()
            || !$this->guardAllowed($event->guard)
            || !config('laravel-waf.login.clear_on_login', true)) {
            return;
        }

        $request = $this->request();
        if ($request === null) {
            return;
        }

        try {
            $ip = $request->ip() ?: 'unknown';
            $identifier = $this->identifier($request, []);
            $this->limiter->clear(RateLimitKey::login($ip, $identifier));
            $this->limiter->clear(RateLimitKey::login($ip));
        } catch (Throwable $exception) {
            $this->metrics->error('login_success_handler');
            $this->warning('Laravel WAF login success handler failed.', [
                'exception' => $exception::class,
            ]);
        }
    }

    /** @param array<string, mixed> $credentials */
    private function identifier(Request $request, array $credentials): string
    {
        $field = config('laravel-waf.login.field', 'email');
        $value = is_string($field) ? $request->input($field) : null;
        if (!is_scalar($value) && is_string($field)) {
            $value = $credentials[$field] ?? '';
        }

        return is_scalar($value) ? (string) $value : '';
    }

    private function finding(Request $request, string $rule, string $source): Finding
    {
        return new Finding(
            'login',
            $rule,
            'high',
            $source,
            null,
            $request->ip() ?: 'unknown',
            RequestContext::routeLabel($request),
            RequestContext::method($request),
        );
    }

    private function request(): ?Request
    {
        if (!app()->bound('request')) {
            return null;
        }

        $request = app('request');

        return $request instanceof Request ? $request : null;
    }

    private function enabled(): bool
    {
        return (bool) config('laravel-waf.login.enabled', true);
    }

    private function guardAllowed(string $guard): bool
    {
        $guards = config('laravel-waf.login.guards', []);

        return !is_array($guards) || $guards === [] || in_array($guard, $guards, true);
    }
    /** @param array<string, string> $context */
    private function warning(string $message, array $context): void
    {
        try {
            $this->logger->warning($message, $context);
        } catch (Throwable) {
            $this->metrics->error('security_logging');
        }
    }
}

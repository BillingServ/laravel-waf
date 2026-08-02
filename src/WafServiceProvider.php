<?php

namespace BillingServ\LaravelWaf;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Http\Responses\AltchaChallengeResponder;
use BillingServ\LaravelWaf\Http\Responses\DefaultChallengeResponder;
use BillingServ\LaravelWaf\Support\AltchaVerifier;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\NullChallengeVerifier;
use BillingServ\LaravelWaf\Support\NullDecisionSink;
use BillingServ\LaravelWaf\Support\NullMetricsSink;
use BillingServ\LaravelWaf\Support\PrometheusMetricsSink;
use BillingServ\LaravelWaf\Support\UnixSocketDecisionSink;
use Illuminate\Cache\Repository;
use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;

final class WafServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/laravel-waf.php', 'laravel-waf');

        $this->app->singleton(Repository::class, fn ($app): Repository => $app->make('cache')->driver());

        $this->app->singleton(MetricsSink::class, function (): MetricsSink {
            if (!config('laravel-waf.metrics.enabled', false)
                || !class_exists('Prometheus\\CollectorRegistry')) {
                return new NullMetricsSink();
            }

            try {
                return new PrometheusMetricsSink(
                    \Prometheus\CollectorRegistry::getDefault(),
                    (string) config('laravel-waf.metrics.namespace', 'laravel_waf'),
                );
            } catch (\Throwable) {
                return new NullMetricsSink();
            }
        });

        $this->app->singleton(MetricsRecorder::class, fn ($app): MetricsRecorder => new MetricsRecorder(
            $app->make(MetricsSink::class),
        ));

        $this->app->singleton(ChallengeTokenManager::class, function (): ChallengeTokenManager {
            $secret = config('laravel-waf.challenge.cookie_secret');
            if (!is_string($secret) || $secret === '') {
                $secret = config('app.key');
            }

            return new ChallengeTokenManager(is_string($secret) ? $secret : null);
        });

        $this->app->singleton(ChallengeVerifier::class, function (): ChallengeVerifier {
            if (config('laravel-waf.challenge.provider', 'default') !== 'altcha') {
                return new NullChallengeVerifier();
            }

            return new AltchaVerifier(
                (string) config('laravel-waf.challenge.altcha.hmac_key', ''),
                (string) config('laravel-waf.challenge.altcha.verification', 'solution'),
                (int) config('laravel-waf.challenge.altcha.max_payload_bytes', 65536),
            );
        });

        $this->app->singleton(DecisionSink::class, function ($app): DecisionSink {
            if (!config('laravel-waf.agent.enabled', false)) {
                return new NullDecisionSink();
            }

            return new UnixSocketDecisionSink(
                (string) config('laravel-waf.agent.socket'),
                config('laravel-waf.agent.secret'),
                (int) config('laravel-waf.agent.timeout_ms', 25),
                $app->make(MetricsRecorder::class),
            );
        });

        $this->app->singleton(ChallengeResponder::class, function ($app): ChallengeResponder {
            $title = (string) config('laravel-waf.challenge.title', 'Additional verification required');
            $message = (string) config('laravel-waf.challenge.message', 'Please complete the verification before continuing.');
            $status = (int) config('laravel-waf.ddos.status', 429);

            if (config('laravel-waf.challenge.provider', 'default') === 'altcha') {
                return new AltchaChallengeResponder(
                    $title,
                    $message,
                    $status,
                    $app->make(ChallengeTokenManager::class),
                );
            }

            return new DefaultChallengeResponder($title, $message, $status);
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/laravel-waf.php' => config_path('laravel-waf.php'),
        ], 'laravel-waf-config');

        if ($this->app->bound('router')) {
            $this->app->make(Router::class)->aliasMiddleware('laravel-waf.ddos', DdosProtection::class);
        }

        if (config('laravel-waf.challenge.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/challenge.php');
        }

        if (config('laravel-waf.metrics.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/metrics.php');
        }
    }
}

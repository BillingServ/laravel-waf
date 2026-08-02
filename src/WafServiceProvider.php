<?php

namespace BillingServ\LaravelWaf;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Http\Controllers\MetricsController;
use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Http\Responses\DefaultChallengeResponder;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\NullDecisionSink;
use BillingServ\LaravelWaf\Support\NullMetricsSink;
use BillingServ\LaravelWaf\Support\PrometheusMetricsSink;
use BillingServ\LaravelWaf\Support\UnixSocketDecisionSink;
use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;

final class WafServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/laravel-waf.php', 'laravel-waf');

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

        $this->app->singleton(ChallengeResponder::class, fn (): ChallengeResponder => new DefaultChallengeResponder(
            (string) config('laravel-waf.challenge.title', 'Additional verification required'),
            (string) config('laravel-waf.challenge.message', 'Please complete the verification before continuing.'),
            (int) config('laravel-waf.ddos.status', 429),
        ));
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/laravel-waf.php' => config_path('laravel-waf.php'),
        ], 'laravel-waf-config');

        if ($this->app->bound('router')) {
            $this->app->make(Router::class)->aliasMiddleware('laravel-waf.ddos', DdosProtection::class);
        }

        if (config('laravel-waf.metrics.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/metrics.php');
        }
    }
}

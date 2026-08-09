<?php

namespace BillingServ\LaravelWaf;

use BillingServ\LaravelWaf\Contracts\AgentMetricsSource;
use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Contracts\GeoIpResolver;
use BillingServ\LaravelWaf\Contracts\InspectionRule;
use BillingServ\LaravelWaf\Contracts\MetricsRenderer;
use BillingServ\LaravelWaf\Contracts\MetricsSink;
use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Http\Middleware\LoginProtection;
use BillingServ\LaravelWaf\Http\Middleware\RequestInspection;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Http\Responses\AltchaChallengeResponder;
use BillingServ\LaravelWaf\Http\Responses\DefaultChallengeResponder;
use BillingServ\LaravelWaf\Security\BehaviorTracker;
use BillingServ\LaravelWaf\Security\LoginProtectionSubscriber;
use BillingServ\LaravelWaf\Security\RequestInputCollector;
use BillingServ\LaravelWaf\Security\RequestRuleEngine;
use BillingServ\LaravelWaf\Security\Rules\CommandInjectionRule;
use BillingServ\LaravelWaf\Security\Rules\CrLfRule;
use BillingServ\LaravelWaf\Security\Rules\GeoRule;
use BillingServ\LaravelWaf\Security\Rules\LdapInjectionRule;
use BillingServ\LaravelWaf\Security\Rules\LfiRule;
use BillingServ\LaravelWaf\Security\Rules\NoSqlInjectionRule;
use BillingServ\LaravelWaf\Security\Rules\RfiRule;
use BillingServ\LaravelWaf\Security\Rules\RoutePolicyRule;
use BillingServ\LaravelWaf\Security\Rules\SensitivePathRule;
use BillingServ\LaravelWaf\Security\Rules\SqlInjectionRule;
use BillingServ\LaravelWaf\Security\Rules\SsrfRule;
use BillingServ\LaravelWaf\Security\Rules\TemplateInjectionRule;
use BillingServ\LaravelWaf\Security\Rules\XssRule;
use BillingServ\LaravelWaf\Support\AgentBlocker;
use BillingServ\LaravelWaf\Support\AltchaVerifier;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\LaravelNotificationSink;
use BillingServ\LaravelWaf\Support\LoopbackAgentMetricsSource;
use BillingServ\LaravelWaf\Support\MaxMindGeoIpResolver;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\NullChallengeVerifier;
use BillingServ\LaravelWaf\Support\NullDecisionSink;
use BillingServ\LaravelWaf\Support\NullGeoIpResolver;
use BillingServ\LaravelWaf\Support\NullMetricsSink;
use BillingServ\LaravelWaf\Support\OutboundUrlGuard;
use BillingServ\LaravelWaf\Support\PrometheusMetricsSink;
use BillingServ\LaravelWaf\Support\PrometheusRegistryRenderer;
use BillingServ\LaravelWaf\Support\SecurityHeaders;
use BillingServ\LaravelWaf\Support\SecurityNotifier;
use BillingServ\LaravelWaf\Support\UnixSocketDecisionSink;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\Repository;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class WafServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/laravel-waf.php', 'laravel-waf');

        $this->app->singleton(Repository::class, fn ($app): Repository => $app->make('cache')->driver());

        if (!$this->app->bound(LoggerInterface::class)) {
            $this->app->singleton(LoggerInterface::class, static fn (): NullLogger => new NullLogger());
        }

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

        $this->app->singleton(MetricsRenderer::class, static fn (): MetricsRenderer => new PrometheusRegistryRenderer());
        $this->app->singleton(AgentMetricsSource::class, static fn (): AgentMetricsSource => new LoopbackAgentMetricsSource(
            (string) config('laravel-waf.metrics.agent.endpoint', 'http://127.0.0.1:9919/metrics'),
            (int) config('laravel-waf.metrics.agent.timeout_ms', 100),
            (int) config('laravel-waf.metrics.agent.max_response_bytes', 1048576),
        ));

        $this->app->singleton(RequestInputCollector::class, static fn (): RequestInputCollector => new RequestInputCollector());

        $this->app->singleton(BehaviorTracker::class, fn ($app): BehaviorTracker => new BehaviorTracker(
            $app->make(RateLimiter::class),
            $app->make(MetricsRecorder::class),
        ));

        $this->app->singleton(SecurityHeaders::class, static fn (): SecurityHeaders => new SecurityHeaders());
        $this->app->singleton(OutboundUrlGuard::class, static fn (): OutboundUrlGuard => new OutboundUrlGuard());

        $this->app->singleton(GeoIpResolver::class, static function (): GeoIpResolver {
            $database = config('laravel-waf.geo.database');
            $readerClass = 'GeoIp2\\Database\\Reader';

            if (!is_string($database) || $database === '' || !is_file($database) || !class_exists($readerClass)) {
                return new NullGeoIpResolver();
            }

            try {
                return new MaxMindGeoIpResolver(new $readerClass($database));
            } catch (\Throwable) {
                return new NullGeoIpResolver();
            }
        });

        $this->app->singleton(RequestRuleEngine::class, function ($app): RequestRuleEngine {
            $inputs = $app->make(RequestInputCollector::class);
            $rules = [];

            $category = static fn (string $name): array => (array) config('laravel-waf.rules.categories.'.$name, []);
            if ((bool) config('laravel-waf.rules.categories.policy.enabled', true)) {
                $rules[] = new RoutePolicyRule();
            }
            if ((bool) config('laravel-waf.rules.categories.xss.enabled', true)) {
                $rules[] = new XssRule($inputs, $category('xss'));
            }
            if ((bool) config('laravel-waf.rules.categories.sqli.enabled', true)) {
                $rules[] = new SqlInjectionRule($inputs, $category('sqli'));
            }
            if ((bool) config('laravel-waf.rules.categories.rfi.enabled', true)) {
                $rules[] = new RfiRule($inputs, $category('rfi'));
            }
            if ((bool) config('laravel-waf.rules.categories.lfi.enabled', true)) {
                $rules[] = new SensitivePathRule();
                $rules[] = new LfiRule($inputs, $category('lfi'));
            }
            if ((bool) config('laravel-waf.rules.categories.command.enabled', true)) {
                $rules[] = new CommandInjectionRule($inputs, $category('command'));
            }
            if ((bool) config('laravel-waf.rules.categories.template.enabled', true)) {
                $rules[] = new TemplateInjectionRule($inputs, $category('template'));
            }
            if ((bool) config('laravel-waf.rules.categories.nosqli.enabled', true)) {
                $rules[] = new NoSqlInjectionRule($inputs, $category('nosqli'));
            }
            if ((bool) config('laravel-waf.rules.categories.ldap.enabled', true)) {
                $rules[] = new LdapInjectionRule($inputs, $category('ldap'));
            }
            if ((bool) config('laravel-waf.rules.categories.http.enabled', true)) {
                $rules[] = new CrLfRule($inputs, $category('http'));
            }
            if ((bool) config('laravel-waf.rules.categories.ssrf.enabled', true)) {
                $rules[] = new SsrfRule($inputs, $category('ssrf'));
            }
            if ((bool) config('laravel-waf.rules.categories.geo.enabled', false)) {
                $rules[] = new GeoRule($app->make(GeoIpResolver::class));
            }

            /** @var array<int, InspectionRule> $rules */
            return new RequestRuleEngine($rules);
        });

        $this->app->singleton(NotificationSink::class, fn ($app): NotificationSink => new LaravelNotificationSink(
            $app,
        ));

        $this->app->singleton(SecurityNotifier::class, fn ($app): SecurityNotifier => new SecurityNotifier(
            $app->make(Repository::class),
            $app->make(NotificationSink::class),
            $app->make(MetricsRecorder::class),
            $app->make(LoggerInterface::class),
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

        $this->app->bind(AgentBlocker::class, fn ($app): AgentBlocker => new AgentBlocker(
            $app->make(RateLimiter::class),
            $app->make(DecisionSink::class),
            $app->make(MetricsRecorder::class),
            $app->make(LoggerInterface::class),
        ));

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

        $this->excludeChallengeCookieFromEncryption();

        if ($this->app->bound('router')) {
            $router = $this->app->make(Router::class);
            $router->aliasMiddleware('laravel-waf', WafProtection::class);
            $router->aliasMiddleware('laravel-waf.inspect', RequestInspection::class);
            $router->aliasMiddleware('laravel-waf.ddos', DdosProtection::class);
            $router->aliasMiddleware('laravel-waf.login', LoginProtection::class);
        }

        if ($this->app->bound('events')) {
            $this->app->make('events')->subscribe(LoginProtectionSubscriber::class);
        }

        if (config('laravel-waf.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/blocked.php');
        }

        if (config('laravel-waf.challenge.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/challenge.php');
        }

        if (config('laravel-waf.metrics.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/metrics.php');
        }
    }

    private function excludeChallengeCookieFromEncryption(): void
    {
        $name = config('laravel-waf.challenge.cookie_name', 'laravel_waf_challenge');
        if (!is_string($name) || preg_match('/^[A-Za-z0-9_\-]+$/', $name) !== 1) {
            return;
        }

        $middleware = 'Illuminate\\Cookie\\Middleware\\EncryptCookies';
        if (class_exists($middleware) && method_exists($middleware, 'except')) {
            $middleware::except($name);
        }
    }
}

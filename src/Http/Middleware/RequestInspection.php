<?php

namespace BillingServ\LaravelWaf\Http\Middleware;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Contracts\DecisionSink;
use BillingServ\LaravelWaf\Http\Responses\ChallengePage;
use BillingServ\LaravelWaf\Security\BehaviorTracker;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Security\RequestRuleEngine;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\SecurityNotifier;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class RequestInspection
{
    public function __construct(
        private readonly RequestRuleEngine $engine,
        private readonly BehaviorTracker $behavior,
        private readonly RateLimiter $limiter,
        private readonly DecisionSink $decisions,
        private readonly ChallengeResponder $challenge,
        private readonly MetricsRecorder $metrics,
        private readonly SecurityNotifier $notifier,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('laravel-waf.enabled', true)) {
            return $next($request);
        }

        $route = $this->routeName($request);
        if (in_array($route, $this->skipRoutes(), true)) {
            return $next($request);
        }

        $findings = [];
        $behaviorFinding = $this->behavior->inspect($request);
        if ($behaviorFinding !== null) {
            $findings[] = $behaviorFinding;
        }

        if (config('laravel-waf.rules.enabled', true)) {
            try {
                $findings = array_merge($findings, $this->engine->inspect($request));
                $findings = array_slice($findings, 0, max(1, min(32, (int) config('laravel-waf.rules.max_findings', 3))));
            } catch (Throwable $exception) {
                $this->metrics->error('request_inspection');
                $this->warning('Laravel WAF request inspection failed.', [
                    'exception' => $exception::class,
                    'route' => $route,
                ]);

                if (config('laravel-waf.rules.fail_mode', 'open') === 'closed') {
                    return $this->unavailable($request);
                }
            }
        }

        $actionable = null;
        foreach ($findings as $finding) {
            $action = $this->action($finding);
            $this->metrics->finding($finding, $action);
            $this->log($finding, $action);
            $this->notifier->notify($finding);
            $this->maybeBlock($finding);

            if ($action !== 'log' && $actionable === null) {
                $actionable = [$finding, $action];
            }
        }

        if ($actionable === null) {
            $response = $next($request);
            $this->behavior->record($request, $response);

            return $response;
        }

        /** @var array{0: Finding, 1: string} $actionable */
        [$finding, $action] = $actionable;
        if ($action === 'challenge' && config('laravel-waf.challenge.enabled', false)) {
            $this->metrics->decision('challenge', 'rule', $finding->route);

            return $this->challenge->respond($request, 60, 'rule_'.$finding->category);
        }

        $this->metrics->decision('blocked', 'rule', $finding->route);

        return $this->blocked($request);
    }

    private function action(Finding $finding): string
    {
        $configured = $finding->category === 'behavior'
            ? config('laravel-waf.behavior.action')
            : config('laravel-waf.rules.categories.'.$finding->category.'.action');
        $action = is_string($configured) && $configured !== ''
            ? $configured
            : config('laravel-waf.rules.mode', 'reject');

        return in_array($action, ['reject', 'challenge', 'log'], true) ? $action : 'reject';
    }

    private function maybeBlock(Finding $finding): void
    {
        if (!config('laravel-waf.agent.enabled', false)
            || !config('laravel-waf.agent.auto_block_on_finding', false)
            || filter_var($finding->ip, FILTER_VALIDATE_IP) === false) {
            return;
        }

        $key = RateLimitKey::securityBlock($finding->ip, $finding->category);
        $cooldown = max(1, (int) config('laravel-waf.agent.block_cooldown_seconds', 60));

        try {
            if ($this->limiter->tooManyAttempts($key, 1)) {
                return;
            }

            $this->limiter->hit($key, $cooldown);
            $this->decisions->block(
                $finding->ip,
                (int) config('laravel-waf.agent.block_ttl_seconds', 900),
                'waf_'.$finding->category,
            );
        } catch (Throwable) {
            $this->metrics->error('agent_decision');
        }
    }

    private function blocked(Request $request): Response
    {
        $status = max(400, min(599, (int) config('laravel-waf.rules.status', 403)));
        $headers = [
            'Cache-Control' => 'no-store',
            'X-Laravel-Waf-Blocked' => 'true',
        ];

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Request blocked.'], $status, $headers);
        }

        $body = ChallengePage::blocked(
            (string) config('laravel-waf.challenge.blocked_title', 'Request blocked'),
            (string) config('laravel-waf.challenge.blocked_message', 'This request was blocked by the site security policy.'),
        );
        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response($body, $status, $headers);
    }

    private function unavailable(Request $request): Response
    {
        $headers = [
            'Cache-Control' => 'no-store',
            'Retry-After' => '5',
        ];

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Request protection is temporarily unavailable.'], 503, $headers);
        }

        return new Response('Request protection is temporarily unavailable.', 503, $headers);
    }

    private function log(Finding $finding, string $action): void
    {
        try {
            $this->logger->warning('Laravel WAF request finding.', $finding->context() + ['action' => $action]);
        } catch (Throwable) {
            $this->metrics->error('security_logging');
        }
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

    /** @return array<int, string> */
    private function skipRoutes(): array
    {
        $routes = config('laravel-waf.rules.skip_routes', []);
        $challengeRoute = config('laravel-waf.challenge.verify_route');
        if (is_string($challengeRoute) && $challengeRoute !== '') {
            $routes[] = $challengeRoute;
        }

        return is_array($routes) ? array_values(array_filter($routes, 'is_string')) : [];
    }

    private function routeName(Request $request): string
    {
        $route = $request->route();

        if (is_object($route) && method_exists($route, 'getName')) {
            return $route->getName() ?: 'unnamed';
        }

        return 'unnamed';
    }
}

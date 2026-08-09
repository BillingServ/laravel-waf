<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\AgentMetricsSource;
use BillingServ\LaravelWaf\Contracts\MetricsRenderer;
use BillingServ\LaravelWaf\Tests\TestCase;

final class MetricsEndpointTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.metrics.enabled', true);
        $app['config']->set('laravel-waf.metrics.route', 'prometheus');
        $app['config']->set('laravel-waf.metrics.allowed_ips', ['100.64.0.10']);
        $app['config']->set('laravel-waf.metrics.agent.enabled', true);
    }

    public function test_allowed_scraper_receives_laravel_and_agent_metrics_from_one_endpoint(): void
    {
        $this->bindRenderer("# TYPE laravel_waf_findings_total counter\nlaravel_waf_findings_total 2\n");
        $this->bindAgent([
            'up' => true,
            'body' => "# TYPE laravel_waf_agent_decisions_total counter\nlaravel_waf_agent_decisions_total 3\n",
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '100.64.0.10'])
            ->get('/prometheus')
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSee('laravel_waf_findings_total 2', false)
            ->assertSee('laravel_waf_agent_metrics_up 1', false)
            ->assertSee('laravel_waf_agent_decisions_total 3', false);

        $this->withServerVariables(['REMOTE_ADDR' => '100.64.0.10'])
            ->get('/_waf/metrics')
            ->assertNotFound();
    }

    public function test_unlisted_scraper_cannot_discover_the_endpoint(): void
    {
        $this->bindRenderer('must-not-leak');
        $this->bindAgent(['up' => true, 'body' => 'must-not-leak']);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/prometheus')
            ->assertNotFound()
            ->assertDontSee('must-not-leak');
    }

    public function test_cidr_allowlist_is_supported(): void
    {
        config()->set('laravel-waf.metrics.allowed_ips', ['100.64.0.0/10']);
        config()->set('laravel-waf.metrics.agent.enabled', false);
        $this->bindRenderer("local_metric 1\n");

        $this->withServerVariables(['REMOTE_ADDR' => '100.100.20.30'])
            ->get('/prometheus')
            ->assertOk()
            ->assertSee('local_metric 1', false)
            ->assertDontSee('laravel_waf_agent_metrics_up', false);
    }

    public function test_empty_allowlist_fails_closed(): void
    {
        config()->set('laravel-waf.metrics.allowed_ips', []);
        $this->bindRenderer('must-not-leak');

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/prometheus')
            ->assertNotFound()
            ->assertDontSee('must-not-leak');
    }

    public function test_agent_failure_is_reported_without_losing_laravel_metrics(): void
    {
        $this->bindRenderer("local_metric 1\n");
        $this->bindAgent(['up' => false, 'body' => '']);

        $this->withServerVariables(['REMOTE_ADDR' => '100.64.0.10'])
            ->get('/prometheus')
            ->assertOk()
            ->assertSee('local_metric 1', false)
            ->assertSee('laravel_waf_agent_metrics_up 0', false);
    }

    public function test_missing_prometheus_support_is_reported_to_an_allowed_scraper(): void
    {
        app()->instance(MetricsRenderer::class, new class implements MetricsRenderer {
            public function available(): bool
            {
                return false;
            }

            public function render(): string
            {
                return '';
            }
        });

        $this->withServerVariables(['REMOTE_ADDR' => '100.64.0.10'])
            ->get('/prometheus')
            ->assertStatus(503)
            ->assertSee('Prometheus support is not installed.');
    }

    private function bindRenderer(string $body): void
    {
        app()->instance(MetricsRenderer::class, new class($body) implements MetricsRenderer {
            public function __construct(private readonly string $body)
            {
            }

            public function available(): bool
            {
                return true;
            }

            public function render(): string
            {
                return $this->body;
            }
        });
    }

    /** @param array{up: bool, body: string} $result */
    private function bindAgent(array $result): void
    {
        app()->instance(AgentMetricsSource::class, new class($result) implements AgentMetricsSource {
            /** @param array{up: bool, body: string} $result */
            public function __construct(private readonly array $result)
            {
            }

            public function collect(): array
            {
                return $this->result;
            }
        });
    }
}

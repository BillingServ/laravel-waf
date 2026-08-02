<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\GeoIpResolver;
use BillingServ\LaravelWaf\Contracts\NotificationSink;
use BillingServ\LaravelWaf\Http\Middleware\LoginProtection;
use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Security\Finding;
use BillingServ\LaravelWaf\Support\SecurityNotifier;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

final class WafRulesTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.rules.enabled', true);
        $app['config']->set('laravel-waf.rules.max_findings', 3);
        $app['config']->set('laravel-waf.rules.categories.geo.enabled', false);
        $app['config']->set('laravel-waf.notifications.enabled', false);
        $app['config']->set('laravel-waf.login.enabled', true);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(WafProtection::class)
            ->match(['GET', 'POST'], '/inspect', static fn () => response('ok'))
            ->name('inspect');

        Route::middleware(LoginProtection::class)
            ->post('/login', static function (Request $request) {
                event(new Failed('web', null, ['email' => $request->input('email')]));

                return response('invalid', 401);
            })
            ->name('login');
    }

    public function test_xss_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.40'])
            ->get('/inspect?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');
    }

    public function test_sql_injection_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.41'])
            ->get('/inspect?q=1%20UNION%20SELECT%20password%20FROM%20users')
            ->assertStatus(403);
    }

    public function test_rfi_is_blocked_for_a_file_like_parameter(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])
            ->get('/inspect?file=https%3A%2F%2Fevil.test%2Fpayload.txt')
            ->assertStatus(403);
    }

    public function test_lfi_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.43'])
            ->get('/inspect?file=..%2F..%2Fetc%2Fpasswd')
            ->assertStatus(403);
    }

    public function test_findings_can_be_logged_without_blocking(): void
    {
        config()->set('laravel-waf.rules.mode', 'log');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.44'])
            ->get('/inspect?name=%3Cscript%3E')
            ->assertOk()
            ->assertContent('ok');
    }

    public function test_geo_policy_uses_a_custom_resolver(): void
    {
        config()->set('laravel-waf.rules.categories.geo.enabled', true);
        config()->set('laravel-waf.geo.allowed_countries', ['GB']);
        $this->app->instance(GeoIpResolver::class, new class implements GeoIpResolver {
            public function country(string $ip): ?string
            {
                return 'US';
            }
        });

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.45'])
            ->get('/inspect')
            ->assertStatus(403);
    }

    public function test_challenge_action_can_be_used_for_a_finding(): void
    {
        config()->set('laravel-waf.rules.categories.xss.action', 'challenge');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.46'])
            ->get('/inspect?name=%3Cscript%3E')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required');
    }

    public function test_notifications_receive_redacted_findings(): void
    {
        config()->set('laravel-waf.notifications.enabled', true);
        $sink = new RecordingNotificationSink();
        $this->app->instance(NotificationSink::class, $sink);
        $this->app->forgetInstance(SecurityNotifier::class);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.47'])
            ->get('/inspect?name=%3Cscript%3Esecret-value%3C%2Fscript%3E')
            ->assertStatus(403);

        self::assertCount(1, $sink->findings);
        self::assertSame('xss', $sink->findings[0]->category);
        self::assertStringNotContainsString('secret-value', json_encode($sink->findings[0]->context(), JSON_THROW_ON_ERROR));
    }

    public function test_login_failures_are_rate_limited(): void
    {
        config()->set('laravel-waf.login.max_attempts', 2);
        config()->set('laravel-waf.login.decay_seconds', 60);

        $server = ['REMOTE_ADDR' => '203.0.113.48'];
        $this->withServerVariables($server)->post('/login', ['email' => 'user@example.test'])->assertStatus(401);
        $this->withServerVariables($server)->post('/login', ['email' => 'user@example.test'])->assertStatus(401);
        $this->withServerVariables($server)->post('/login', ['email' => 'user@example.test'])->assertStatus(429);
    }
}

final class RecordingNotificationSink implements NotificationSink
{
    /** @var array<int, Finding> */
    public array $findings = [];

    public function notify(Finding $finding): void
    {
        $this->findings[] = $finding;
    }
}

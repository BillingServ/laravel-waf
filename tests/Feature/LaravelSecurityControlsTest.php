<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Support\Facades\Route;

final class LaravelSecurityControlsTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.behavior.enabled', true);
        $app['config']->set('laravel-waf.behavior.thresholds', [
            '404' => 2,
            '405' => 20,
            '401' => 20,
            '403' => 30,
            'client_error' => 100,
        ]);
        $app['config']->set('laravel-waf.behavior.action', 'reject');
        $app['config']->set('laravel-waf.policies.enabled', false);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(WafProtection::class)
            ->get('/headers', static fn () => response('ok'))
            ->name('headers');

        Route::middleware(WafProtection::class)
            ->get('/custom-headers', static function () {
                return response('ok')->header('X-Frame-Options', 'DENY');
            })
            ->name('custom-headers');

        Route::middleware(WafProtection::class)
            ->match(['GET', 'POST'], '/policy', static fn () => response('ok'))
            ->name('policy');

        Route::middleware(WafProtection::class)
            ->get('/gone', static fn () => response('gone', 404))
            ->name('gone');
    }

    public function test_standard_security_headers_are_added(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.60'])
            ->get('/headers')
            ->assertOk()
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Frame-Options', 'SAMEORIGIN')
            ->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    }

    public function test_application_security_headers_are_preserved(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.61'])
            ->get('/custom-headers')
            ->assertOk()
            ->assertHeader('X-Frame-Options', 'DENY');
    }

    public function test_hsts_is_only_added_to_secure_requests(): void
    {
        config()->set('laravel-waf.security_headers.hsts.enabled', true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.62'])
            ->get('https://localhost/headers')
            ->assertOk()
            ->assertHeader('Strict-Transport-Security', 'max-age=31536000');
    }

    public function test_route_policy_can_reject_a_method(): void
    {
        config()->set('laravel-waf.policies.enabled', true);
        config()->set('laravel-waf.policies.routes.policy', ['methods' => ['POST']]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.63'])
            ->get('/policy')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');
    }

    public function test_route_policy_can_require_auth_middleware(): void
    {
        config()->set('laravel-waf.policies.enabled', true);
        config()->set('laravel-waf.policies.routes.policy', ['require_auth' => true]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.64'])
            ->get('/policy')
            ->assertStatus(403);
    }

    public function test_repeated_not_found_responses_trigger_behavior_protection(): void
    {
        config()->set('laravel-waf.ddos.enabled', false);

        $server = ['REMOTE_ADDR' => '203.0.113.65'];
        $this->withServerVariables($server)->get('/gone')->assertStatus(404);
        $this->withServerVariables($server)->get('/gone')->assertStatus(404);

        $this->withServerVariables($server)
            ->get('/gone')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');

        $this->withServerVariables($server)
            ->get('/gone')
            ->assertStatus(403)
            ->assertHeader('X-Laravel-Waf-Blocked', 'true');
    }
}

<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Http\Middleware\DdosProtection;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Support\Facades\Route;

final class DdosProtectionTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        Route::middleware(DdosProtection::class)
            ->get('/limited', static fn () => response('ok'))
            ->name('limited');
    }

    public function test_route_limit_returns_too_many_requests(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk()
            ->assertHeader('X-RateLimit-Remaining', '1');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk()
            ->assertHeader('X-RateLimit-Remaining', '0');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeader('X-RateLimit-Remaining', '0');
    }

    public function test_different_clients_have_independent_limits(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.11'])
            ->get('/limited')
            ->assertOk();
    }

    public function test_challenge_mode_returns_a_challenge_response(): void
    {
        config()->set('laravel-waf.ddos.mode', 'challenge');
        config()->set('laravel-waf.challenge.enabled', true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited');
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited');

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/limited')
            ->assertStatus(429)
            ->assertHeader('X-Laravel-Waf-Challenge', 'required')
            ->assertSee('Additional verification required');
    }
}

<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Http\Middleware\WafProtection;
use BillingServ\LaravelWaf\Support\RateLimiter;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

final class StateChangingRequestChallengeTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.ddos.mode', 'challenge');
        $app['config']->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 100, 'decay_seconds' => 60]]);
        $app['config']->set('laravel-waf.ddos.burst.enabled', false);
        $app['config']->set('laravel-waf.ddos.adaptive.enabled', true);
        $app['config']->set('laravel-waf.ddos.adaptive.challenge_after', 1);
        $app['config']->set('laravel-waf.rules.mode', 'reject');
        $app['config']->set('laravel-waf.notifications.enabled', false);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware([WafProtection::class, 'web'])->group(function (): void {
            Route::post('/login', static function (Request $request) {
                $request->session()->put('signed_in', true);

                return redirect('/account');
            })->name('login');
            Route::post('/logout', static function (Request $request) {
                $request->session()->put('signed_in', false);

                return redirect('/login');
            })->name('logout');
            Route::post('/cart', static function (Request $request) {
                $request->session()->increment('cart_quantity');

                return redirect('/cart');
            })->name('cart.add');
            Route::post('/livewire/update', static function (Request $request) {
                $request->session()->put('action_completed', true);

                return response()->json(['components' => []]);
            })->name('livewire.update');
            Route::get('/{page}', static fn () => response('page'))->name('page');
            Route::options('/cart', static fn () => response('', 204))->name('cart.options');
        });
    }

    public static function mutations(): array
    {
        return [
            'login' => ['/login', 'signed_in', true],
            'logout' => ['/logout', 'signed_in', false],
            'cart' => ['/cart', 'cart_quantity', 1],
        ];
    }

    #[DataProvider('mutations')]
    public function test_mutations_complete_before_the_following_page_is_challenged(string $path, string $key, bool|int $value): void
    {
        app(RateLimiter::class)->hit(RateLimitKey::trafficPressure(), 60);
        app(RateLimiter::class)->hit(RateLimitKey::trafficPressure(), 60);

        $response = $this->withSession(['signed_in' => true])->post($path);

        $response->assertRedirect()->assertHeaderMissing('X-Laravel-Waf-Challenge')->assertSessionHas($key, $value);
        $this->get($response->headers->get('Location'))
            ->assertStatus(429)->assertHeader('X-Laravel-Waf-Challenge', 'required');
    }

    public function test_livewire_mutations_run_instead_of_receiving_a_challenge_redirect_effect(): void
    {
        app(RateLimiter::class)->hit(RateLimitKey::trafficPressure(), 60);
        app(RateLimiter::class)->hit(RateLimitKey::trafficPressure(), 60);

        $this->withHeader('X-Livewire', 'true')->postJson('/livewire/update', [
            'components' => [['snapshot' => '{}', 'updates' => [], 'calls' => [['method' => 'authenticate', 'params' => []]]]],
        ])->assertOk()->assertExactJson(['components' => []])->assertSessionHas('action_completed', true);
    }

    public function test_client_limits_still_reject_repeated_mutations_without_redirecting_them(): void
    {
        config()->set('laravel-waf.ddos.adaptive.enabled', false);
        config()->set('laravel-waf.ddos.routes', ['*' => ['max_attempts' => 1, 'decay_seconds' => 60]]);
        $this->post('/cart')->assertRedirect()->assertSessionHas('cart_quantity', 1);

        $this->post('/cart')->assertStatus(429)
            ->assertHeaderMissing('X-Laravel-Waf-Challenge')->assertSessionHas('cart_quantity', 1);
    }

    public function test_request_inspection_still_rejects_malicious_mutations(): void
    {
        $this->withSession(['signed_in' => false])->post('/login', ['input' => '<script>alert(1)</script>'])
            ->assertStatus(403)->assertSessionHas('signed_in', false);
    }

    public function test_preflight_requests_do_not_receive_a_browser_challenge(): void
    {
        app(RateLimiter::class)->hit(RateLimitKey::trafficPressure(), 60);
        app(RateLimiter::class)->hit(RateLimitKey::trafficPressure(), 60);

        $this->options('/cart')->assertNoContent()->assertHeaderMissing('X-Laravel-Waf-Challenge');
    }
}

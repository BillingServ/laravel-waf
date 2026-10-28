<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Support\RateLimitKey;
use BillingServ\LaravelWaf\Support\RateLimiter;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GenericUser;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Http\Request;

final class LoginProtectionTest extends TestCase
{
    public function test_successful_livewire_login_clears_the_failed_identity_and_ip_windows(): void
    {
        $this->bindRequest(['components' => [['updates' => ['data.email' => 'user@example.test']]]]);
        $limiter = app(RateLimiter::class);
        $identityKey = RateLimitKey::login('203.0.113.10', 'user@example.test');
        $ipKey = RateLimitKey::login('203.0.113.10');
        event(new Failed('web', null, ['email' => 'user@example.test']));
        self::assertSame(1, $limiter->attempts($identityKey));
        self::assertSame(1, $limiter->attempts($ipKey));

        event(new Login('web', new GenericUser(['id' => 1, 'email' => 'user@example.test']), false));

        foreach ([$identityKey, $ipKey] as $key) {
            self::assertSame(0, $limiter->attempts($key));
            self::assertNull(cache()->get($key.':timer'));
        }
    }

    public function test_form_login_keeps_the_submitted_identifier_when_the_user_value_differs(): void
    {
        $this->bindRequest(['email' => 'alias@example.test']);
        $limiter = app(RateLimiter::class);
        $submittedKey = RateLimitKey::login('203.0.113.10', 'alias@example.test');
        $canonicalKey = RateLimitKey::login('203.0.113.10', 'canonical@example.test');
        $limiter->hit($submittedKey, 60);
        $limiter->hit($canonicalKey, 60);

        event(new Login('web', new GenericUser(['id' => 1, 'email' => 'canonical@example.test']), false));

        self::assertSame(0, $limiter->attempts($submittedKey));
        self::assertSame(1, $limiter->attempts($canonicalKey));
    }

    public function test_livewire_login_uses_the_configured_identifier_on_the_authenticated_user(): void
    {
        config()->set('laravel-waf.login.field', 'username');
        $this->bindRequest(['components' => [['updates' => ['data.username' => 'user-name']]]]);
        $limiter = app(RateLimiter::class);
        $key = RateLimitKey::login('203.0.113.10', 'user-name');
        event(new Failed('web', null, ['username' => 'user-name']));

        event(new Login('web', new GenericUser(['id' => 1, 'username' => 'user-name']), false));

        self::assertSame(0, $limiter->attempts($key));
        self::assertNull(cache()->get($key.':timer'));
    }

    public function test_missing_identifier_clears_each_cache_key_only_once(): void
    {
        $this->bindRequest(['components' => []]);
        $store = new RecordingLoginCacheStore();
        app('cache')->extend('recording-login', static fn () => new Repository($store));
        config()->set('cache.stores.recording-login', ['driver' => 'recording-login']);
        config()->set('cache.limiter', 'recording-login');
        $key = RateLimitKey::login('203.0.113.10');

        event(new Login('web', new GenericUser(['id' => 1]), false));

        self::assertSame([$key, $key.':timer'], $store->forgotten);
    }

    public function test_clear_on_login_can_be_disabled(): void
    {
        config()->set('laravel-waf.login.clear_on_login', false);
        $this->bindRequest([]);
        $limiter = app(RateLimiter::class);
        $key = RateLimitKey::login('203.0.113.10', 'user@example.test');
        $limiter->hit($key, 60);

        event(new Login('web', new GenericUser(['id' => 1, 'email' => 'user@example.test']), false));

        self::assertSame(1, $limiter->attempts($key));
    }

    public function test_excluded_guards_do_not_clear_login_windows(): void
    {
        config()->set('laravel-waf.login.guards', ['admin']);
        $this->bindRequest([]);
        $limiter = app(RateLimiter::class);
        $key = RateLimitKey::login('203.0.113.10', 'user@example.test');
        $limiter->hit($key, 60);

        event(new Login('web', new GenericUser(['id' => 1, 'email' => 'user@example.test']), false));

        self::assertSame(1, $limiter->attempts($key));
    }

    public function test_bulk_clear_preserves_other_counters_and_their_timers(): void
    {
        $limiter = app(RateLimiter::class);
        $limiter->hit('first', 60);
        $limiter->hit('second', 60);

        $limiter->clearMany(['first', 'first']);

        self::assertSame(0, $limiter->attempts('first'));
        self::assertNull(cache()->get('first:timer'));
        self::assertSame(1, $limiter->attempts('second'));
        self::assertNotNull(cache()->get('second:timer'));
    }

    /** @param array<string, mixed> $payload */
    private function bindRequest(array $payload): void
    {
        app()->instance('request', Request::create('/livewire/update', 'POST', $payload, [], [], [
            'REMOTE_ADDR' => '203.0.113.10',
        ]));
    }
}

final class RecordingLoginCacheStore extends ArrayStore
{
    /** @var array<int, string> */
    public array $forgotten = [];

    public function forget($key): bool
    {
        $this->forgotten[] = $key;

        return parent::forget($key);
    }
}

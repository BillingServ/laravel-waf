<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Http\Responses\AltchaChallengeResponder;
use BillingServ\LaravelWaf\Http\Responses\LivewireResponse;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\SameOriginUrl;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

final class SameOriginUrlTest extends TestCase
{
    public function test_named_routes_remain_same_origin_and_retain_the_request_base_url(): void
    {
        Route::get('/_waf/internal/{id}', static fn () => response('ok'))
            ->name('same-origin-url.test');
        $this->app['url']->forceRootUrl('https://configured-origin.example/old');

        $rewritten = Request::create('/app/login', 'GET', [], [], [], [
            'SCRIPT_NAME' => '/app/index.php',
            'SCRIPT_FILENAME' => '/var/www/app/index.php',
        ]);
        $frontController = Request::create('/app/index.php/login', 'GET', [], [], [], [
            'SCRIPT_NAME' => '/app/index.php',
            'SCRIPT_FILENAME' => '/var/www/app/index.php',
        ]);
        $root = Request::create('/login');

        self::assertSame(
            '/app/_waf/internal/42?token=value',
            SameOriginUrl::route($rewritten, 'same-origin-url.test', [
                'id' => 42,
                'token' => 'value',
            ]),
        );
        self::assertSame(
            '/app/index.php/_waf/internal/42',
            SameOriginUrl::route($frontController, 'same-origin-url.test', ['id' => 42]),
        );
        self::assertSame(
            '/_waf/internal/42',
            SameOriginUrl::route($root, 'same-origin-url.test', ['id' => 42]),
        );
    }

    public function test_package_browser_flows_ignore_a_different_forced_root_path(): void
    {
        $this->app['url']->forceRootUrl('https://configured-origin.example/old');
        config()->set('laravel-waf.challenge.altcha.challenge_url', 'https://configured-origin.example/altcha');
        $server = [
            'REMOTE_ADDR' => '203.0.113.80',
            'SCRIPT_NAME' => '/app/index.php',
            'SCRIPT_FILENAME' => '/var/www/app/index.php',
        ];
        $snapshot = json_encode([
            'data' => [],
            'memo' => ['id' => 'test-component', 'name' => 'login', 'children' => []],
            'checksum' => 'test-checksum',
        ], JSON_THROW_ON_ERROR);
        $livewireRequest = Request::create('/app/livewire/update', 'POST', [
            'components' => [[
                'snapshot' => $snapshot,
                'updates' => [],
                'calls' => [],
            ]],
        ], [], [], $server);
        $livewireRequest->headers->set('X-Livewire', 'true');
        $responder = new AltchaChallengeResponder(
            'Checking your browser',
            'Please wait.',
            429,
            $this->app->make(ChallengeTokenManager::class),
        );

        $challenge = $responder->respond($livewireRequest, 60, 'adaptive');
        self::assertSame(200, $challenge->getStatusCode());
        $challengeData = json_decode((string) $challenge->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertStringStartsWith(
            '/app/_waf/challenge?_waf_challenge=',
            $challengeData['components'][0]['effects']['redirect'],
        );

        $blocked = LivewireResponse::blocked($livewireRequest);
        self::assertNotNull($blocked);
        $blockedData = json_decode((string) $blocked->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('/app/_waf/blocked', $blockedData['components'][0]['effects']['redirect']);

        $pageRequest = Request::create('/app/account', 'GET', [], [], [], $server);
        $page = $responder->respond($pageRequest, 60, 'adaptive');
        self::assertSame(429, $page->getStatusCode());
        self::assertStringContainsString(
            'action="/app/_waf/challenge/verify"',
            (string) $page->getContent(),
        );
    }

    public function test_request_base_path_is_not_duplicated_without_a_forced_root(): void
    {
        Route::get('/_waf/internal', static fn () => response('ok'))
            ->name('same-origin-url.request-root');
        $request = Request::create('/app/login', 'GET', [], [], [], [
            'SCRIPT_NAME' => '/app/index.php',
            'SCRIPT_FILENAME' => '/var/www/app/index.php',
        ]);
        $this->app['url']->setRequest($request);

        self::assertSame(
            '/app/_waf/internal',
            SameOriginUrl::route($request, 'same-origin-url.request-root'),
        );
    }

    public function test_generated_url_length_remains_bounded_after_adding_the_base_url(): void
    {
        Route::get('/_waf/internal', static fn () => response('ok'))
            ->name('same-origin-url.length');
        $request = Request::create('/application/login', 'GET', [], [], [], [
            'SCRIPT_NAME' => '/application/index.php',
            'SCRIPT_FILENAME' => '/var/www/application/index.php',
        ]);

        self::assertNull(SameOriginUrl::route(
            $request,
            'same-origin-url.length',
            [],
            strlen('/application/_waf/internal') - 1,
        ));
    }
}

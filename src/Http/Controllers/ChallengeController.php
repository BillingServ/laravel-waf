<?php

namespace BillingServ\LaravelWaf\Http\Controllers;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use BillingServ\LaravelWaf\Http\Responses\BlockedResponse;
use BillingServ\LaravelWaf\Http\Responses\ChallengePage;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\MetricsRecorder;
use BillingServ\LaravelWaf\Support\RateLimitKey;
use Illuminate\Cache\Repository;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class ChallengeController
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly Repository $cache,
        private readonly ChallengeResponder $challenge,
        private readonly ChallengeVerifier $verifier,
        private readonly ChallengeTokenManager $tokens,
        private readonly MetricsRecorder $metrics,
    ) {
    }

    public function show(Request $request): Response
    {
        $ip = $request->ip() ?: 'unknown';
        $token = $request->query('_waf_challenge');
        $returnTo = is_string($token)
            ? $this->tokens->requestReturnTo($token, $ip)
            : null;

        if ($returnTo === null) {
            return $this->invalidPage();
        }

        // The page route is used when an AJAX/Livewire request needs to move
        // the browser check to the top-level window. Keep the original safe
        // destination in a request attribute so the responder can issue a
        // fresh, form-postable challenge token for it.
        $request->attributes->set('laravel-waf.challenge_return_to', $returnTo);

        return $this->challenge->respond($request, 60, 'livewire');
    }

    public function verify(Request $request): Response
    {
        $ip = $request->ip() ?: 'unknown';
        $maxAttempts = max(1, (int) config('laravel-waf.challenge.max_attempts', 10));
        $decaySeconds = max(1, (int) config('laravel-waf.challenge.decay_seconds', 60));
        $key = RateLimitKey::challenge($ip);

        try {
            if ($this->limiter->tooManyAttempts($key, $maxAttempts)) {
                $this->metrics->decision('challenge_rate_limited', 'challenge', 'challenge');

                return $this->rateLimited($request, max(1, $this->limiter->availableIn($key)));
            }

            $this->limiter->hit($key, $decaySeconds);
        } catch (Throwable) {
            $this->metrics->error('challenge_rate_limiter');

            return $this->unavailable($request);
        }

        $field = $this->field();
        $payload = $request->input($field);
        $requestToken = $request->input('_waf_challenge');
        $returnTo = is_string($requestToken)
            ? $this->tokens->requestReturnTo($requestToken, $ip)
            : null;

        if ($returnTo === null || ! $this->verifier->verify($payload)) {
            $this->metrics->decision('challenge_rejected', 'challenge', 'challenge');

            return $this->rejected($request, $returnTo);
        }

        try {
            $consumed = $this->cache->add(
                RateLimitKey::challengeToken((string) $requestToken),
                true,
                max(1, (int) config('laravel-waf.challenge.request_token_ttl_seconds', 600)),
            );

            $payloadKey = is_string($payload)
                ? $payload
                : json_encode($payload, JSON_THROW_ON_ERROR);
            $replayFree = $this->cache->add(
                RateLimitKey::challengePayload((string) $payloadKey),
                true,
                max(1, (int) config('laravel-waf.challenge.replay_ttl_seconds', 600)),
            );

            if (! $consumed || ! $replayFree) {
                $this->metrics->decision('challenge_replay', 'challenge', 'challenge');

                return $this->rejected($request, $returnTo);
            }
        } catch (Throwable) {
            $this->metrics->error('challenge_replay_store');

            return $this->unavailable($request);
        }

        $passTtl = max(1, min(86400, (int) config('laravel-waf.challenge.cookie_ttl_seconds', 600)));
        $pass = $this->tokens->issuePass($ip, $passTtl);
        if ($pass === null) {
            $this->metrics->error('challenge_cookie');

            return $this->unavailable($request);
        }

        $response = new RedirectResponse($returnTo, 303);
        $response->headers->setCookie($this->cookie($pass, $passTtl, $request));
        $this->metrics->decision('challenge_passed', 'challenge', 'challenge');

        return $response;
    }

    public function blocked(Request $request): Response
    {
        return BlockedResponse::make(
            $request,
            includeBlockedFlag: true,
            supportLivewire: false,
        );
    }

    private function field(): string
    {
        $field = config('laravel-waf.challenge.altcha.field', 'altcha');

        return is_string($field) && preg_match('/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/', $field) === 1
            ? $field
            : 'altcha';
    }

    private function cookie(string $value, int $ttl, Request $request): Cookie
    {
        $name = config('laravel-waf.challenge.cookie_name', 'laravel_waf_challenge');
        $name = is_string($name) && preg_match('/^[A-Za-z0-9_\-]+$/', $name) === 1
            ? $name
            : 'laravel_waf_challenge';
        $sameSite = strtolower((string) config('laravel-waf.challenge.cookie_same_site', 'lax'));
        $sameSite = in_array($sameSite, ['lax', 'strict', 'none'], true) ? $sameSite : 'lax';
        $secure = filter_var(config('laravel-waf.challenge.cookie_secure', 'auto'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        $secure = $secure ?? $request->isSecure();

        if ($sameSite === 'none') {
            $secure = true;
        }

        return new Cookie($name, $value, time() + $ttl, '/', null, $secure, true, false, $sameSite);
    }

    private function rateLimited(Request $request, int $retryAfter): Response
    {
        $headers = [
            'Cache-Control' => 'no-store',
            'Retry-After' => (string) $retryAfter,
        ];

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Too Many Requests'], 429, $headers);
        }

        return new Response('Too Many Requests', 429, $headers);
    }

    private function rejected(Request $request, ?string $retryUrl = null): Response
    {
        $headers = ['Cache-Control' => 'no-store'];

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Challenge verification failed.'], 422, $headers);
        }

        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response(
            ChallengePage::failed(
                (string) config('laravel-waf.challenge.failure_title', 'Verification failed'),
                (string) config('laravel-waf.challenge.failure_message', 'We could not confirm this request. Please try again.'),
                $retryUrl,
            ),
            422,
            $headers,
        );
    }

    private function unavailable(Request $request): Response
    {
        $headers = [
            'Cache-Control' => 'no-store',
            'Retry-After' => '5',
        ];

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'Challenge verification is temporarily unavailable.'], 503, $headers);
        }

        return new Response('Challenge verification is temporarily unavailable.', 503, $headers);
    }

    private function invalidPage(): Response
    {
        return new Response(
            ChallengePage::failed(
                (string) config('laravel-waf.challenge.failure_title', 'Verification failed'),
                (string) config('laravel-waf.challenge.failure_message', 'We could not confirm this request. Please try again.'),
            ),
            422,
            [
                'Cache-Control' => 'no-store',
                'Content-Type' => 'text/html; charset=UTF-8',
            ],
        );
    }
}

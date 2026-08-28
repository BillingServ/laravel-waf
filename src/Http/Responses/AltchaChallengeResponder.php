<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use BillingServ\LaravelWaf\Support\RequestId;
use BillingServ\LaravelWaf\Support\SameOriginUrl;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class AltchaChallengeResponder implements ChallengeResponder
{
    private const MAX_GENERATED_CHALLENGE_URL_LENGTH = 8192;

    public function __construct(
        private readonly string $title,
        private readonly string $message,
        private readonly int $status,
        private readonly ChallengeTokenManager $tokens,
    ) {
    }

    public function respond(Request $request, int $retryAfter, string $scope): Response
    {
        $headers = [
            'Cache-Control' => 'no-store',
            'Retry-After' => (string) max(1, $retryAfter),
            'X-Laravel-Waf-Challenge' => 'required',
        ];

        if ($scope === 'test') {
            return BlockedResponse::make($request, includeBlockedFlag: true, scope: 'test');
        }

        $requestId = RequestId::make();
        $headers['X-Request-ID'] = $requestId;

        $field = $this->field();
        $challengeUrl = $this->safeUrl(config('laravel-waf.challenge.altcha.challenge_url'));
        $returnTo = $this->returnTo($request);
        $ip = $request->ip() ?: 'unknown';
        $tokenTtl = (int) config('laravel-waf.challenge.request_token_ttl_seconds', 600);
        $token = $this->tokens->issueRequest(
            $ip,
            $returnTo,
            $tokenTtl,
        );
        if ($token === null && $returnTo !== '/') {
            $token = $this->tokens->issueRequest($ip, '/', $tokenTtl);
        }
        $verifyUrl = $this->verifyUrl($request);

        if ($token === null || $verifyUrl === null) {
            return $this->unavailable($request, $headers);
        }

        $livewireRequest = $request->hasHeader('X-Livewire');
        if ($challengeUrl === null && ($livewireRequest || !$request->expectsJson())) {
            return $this->unavailable($request, $headers);
        }

        if ($livewireRequest) {
            $challengePageUrl = $this->challengePageUrl($request, $token);
            if ($challengePageUrl !== null) {
                $livewire = LivewireResponse::challenge($request, $challengePageUrl, $headers);
                if ($livewire !== null) {
                    return $livewire;
                }
            }
        }

        if ($request->expectsJson()) {
            return new JsonResponse([
                'message' => $this->message,
                'challenge' => true,
                'provider' => 'altcha',
                'scope' => $scope,
                'field' => $field,
                'verification_url' => $verifyUrl,
                'challenge_token' => $token,
            ], $this->status, $headers);
        }

        if ($challengeUrl === null) {
            return $this->unavailable($request, $headers);
        }

        $widget = $this->widget($challengeUrl, $field);
        $script = $this->script().$this->autoSubmitScript();
        $automatic = $this->automatic();

        $body = ChallengePage::required(
            $this->title,
            $this->message,
            $verifyUrl,
            $token,
            $widget,
            $script,
            $automatic,
            $requestId,
        );

        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response($body, $this->status, $headers);
    }
    private function widget(string $challengeUrl, string $field): string
    {
        $attribute = config('laravel-waf.challenge.altcha.challenge_attribute', 'challengeurl');
        $attribute = in_array($attribute, ['challengeurl', 'challenge'], true) ? $attribute : 'challengeurl';
        $attributes = [
            $attribute => $challengeUrl,
            'name' => $field,
        ];

        $auto = strtolower((string) config('laravel-waf.challenge.altcha.auto', 'onsubmit'));
        $attributes['auto'] = in_array($auto, ['off', 'onfocus', 'onload', 'onsubmit'], true)
            ? $auto
            : 'onsubmit';

        if ((bool) config('laravel-waf.challenge.altcha.hide_logo', true)) {
            $attributes['hidelogo'] = null;
        }

        $display = strtolower(trim((string) config('laravel-waf.challenge.altcha.display', '')));
        if (in_array($display, ['standard', 'bar', 'floating', 'overlay', 'invisible'], true)) {
            $attributes['display'] = $display;
        }
        if ($display === 'invisible') {
            $attributes['aria-hidden'] = 'true';
            $attributes['tabindex'] = '-1';
        }

        $html = '<altcha-widget';
        foreach ($attributes as $name => $value) {
            $html .= ' '.$name;
            if ($value !== null) {
                $html .= '="'.$this->escape((string) $value).'"';
            }
        }

        return $html.'></altcha-widget>';
    }

    private function script(): string
    {
        $url = $this->safeUrl(config('laravel-waf.challenge.altcha.script_url'));
        if ($url === null) {
            return '';
        }

        $attributes = ' async defer src="'.$this->escape($url).'" type="module"';
        $integrity = config('laravel-waf.challenge.altcha.script_integrity');
        if (is_string($integrity) && preg_match('/^(sha256|sha384|sha512)-[A-Za-z0-9+/_=-]+$/', $integrity)) {
            $attributes .= ' integrity="'.$this->escape($integrity).'" crossorigin="anonymous"';
        }

        return '<script'.$attributes.'></script>';
    }

    private function autoSubmitScript(): string
    {
        if (!config('laravel-waf.challenge.altcha.auto_submit', false)) {
            return '';
        }

        $field = json_encode(
            $this->field(),
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
        );

        return '<script>window.addEventListener("load",function(){'
            .'var widget=document.querySelector("altcha-widget");'
            .'var form=widget&&widget.closest("form");'
            .'if(!widget||!form){return;}'
            .'var page=form.closest("[data-page-state]");'
            .'var shell=form.querySelector(".widget-shell");'
            .'var label=form.querySelector("[data-verification-label]");'
            .'var detail=form.querySelector("[data-verification-detail]");'
            .'var fallback=form.querySelector("[data-verification-fallback]");'
            .'var retry=form.querySelector(".verification-retry");'
            .'var originalDisplay=widget.getAttribute("display")||"";'
            .'var fieldName='.$field.';'
            .'var submitted=false;'
            .'var slowTimer=null;'
            .'var setState=function(state,title,message){'
            .'form.setAttribute("data-verification-state",state);'
            .'if(page){page.setAttribute("data-verification-state",state);}'
            .'if(label){label.textContent=title;}'
            .'if(detail){detail.textContent=message;}'
            .'};'
            .'var showRetry=function(){'
            .'if(fallback){fallback.hidden=false;}'
            .'if(retry){retry.hidden=false;}'
            .'};'
            .'var revealWidget=function(){'
            .'form.classList.add("requires-interaction");'
            .'if(shell){shell.removeAttribute("aria-hidden");}'
            .'widget.setAttribute("aria-hidden","false");'
            .'if(originalDisplay==="invisible"){widget.setAttribute("display","standard");}'
            .'};'
            .'var fail=function(){'
            .'clearTimeout(slowTimer);'
            .'setState("failed","We could not complete the check","Reload the page to try again.");'
            .'showRetry();'
            .'};'
            .'setState("verifying","Checking your browser","This usually takes only a few seconds.");'
            .'slowTimer=setTimeout(function(){'
            .'if(!submitted){'
            .'setState("delayed","This is taking longer than expected","You can restart the check if it does not finish.");'
            .'showRetry();'
            .'}'
            .'},15000);'
            .'var storePayload=function(payload){'
            .'if(payload===undefined||payload===null||payload===""){return false;}'
            .'var value=typeof payload==="string"?payload:JSON.stringify(payload);'
            .'var input=form.querySelector("input[data-altcha-payload]");'
            .'if(!input){input=document.createElement("input");input.type="hidden";'
            .'input.name=fieldName;input.setAttribute("data-altcha-payload","");'
            .'form.appendChild(input);}'
            .'input.value=value;return true;'
            .'};'
            .'var submit=function(payload){if(submitted||!storePayload(payload)){return;}'
            .'submitted=true;clearTimeout(slowTimer);'
            .'setState("verified","Check complete","Continuing…");'
            .'if(fallback){fallback.hidden=true;}'
            .'if(retry){retry.hidden=true;}'
            .'setTimeout(function(){form.submit();},120);};'
            .'widget.addEventListener("statechange",function(event){'
            .'var state=event.detail&&event.detail.state;'
            .'if(state==="verifying"){'
            .'setState("verifying","Checking your browser","This usually takes only a few seconds.");'
            .'}else if(state==="verified"){'
            .'submit(event.detail.payload);'
            .'}else if(state==="code"){'
            .'clearTimeout(slowTimer);revealWidget();'
            .'setState("interaction","Complete the browser check","One more step is required to continue.");'
            .'}else if(state==="error"||state==="unverified"||state==="expired"){fail();}'
            .'});'
            .'widget.addEventListener("verified",function(event){'
            .'if(event.detail){submit(event.detail.payload);}'
            .'});'
            .'if(retry){retry.addEventListener("click",function(){'
            .'window.location.reload();'
            .'});}'
            .'});</script>';
    }

    private function automatic(): bool
    {
        return (bool) config('laravel-waf.challenge.altcha.auto_submit', false)
            && strtolower((string) config('laravel-waf.challenge.altcha.auto', 'onsubmit')) === 'onload'
            && strtolower((string) config('laravel-waf.challenge.altcha.display', '')) === 'invisible';
    }

    private function verifyUrl(Request $request): ?string
    {
        $route = config('laravel-waf.challenge.verify_route');
        if (!is_string($route) || $route === '') {
            return null;
        }

        return SameOriginUrl::route($request, $route);
    }

    private function challengePageUrl(Request $request, string $token): ?string
    {
        // The signed token can contain an accepted return path of up to 2048
        // bytes. Base64 encoding legitimately makes the internal challenge
        // URL longer than the cap used for configured URLs.
        return SameOriginUrl::route(
            $request,
            'laravel-waf.challenge.page',
            ['_waf_challenge' => $token],
            self::MAX_GENERATED_CHALLENGE_URL_LENGTH,
        );
    }

    private function returnTo(Request $request): string
    {
        $attribute = $request->attributes->get('laravel-waf.challenge_return_to');
        if (is_string($attribute) && $this->localUrl($attribute) !== null) {
            return $attribute;
        }

        if (in_array(strtoupper($request->getMethod()), ['GET', 'HEAD'], true)) {
            return $this->localUrl($request->getRequestUri()) ?? '/';
        }

        // State-changing requests cannot be replayed safely after a browser
        // check. Return to the page containing the form instead of sending a
        // challenged login request to an unrelated home page.
        $referer = $request->headers->get('referer');
        if (is_string($referer)) {
            $localReferer = $this->sameOriginPath($request, $referer);
            if ($localReferer !== null) {
                return $localReferer;
            }
        }

        return '/';
    }

    private function localUrl(?string $url): ?string
    {
        if (!is_string($url)
            || $url === ''
            || strlen($url) > 2048
            || str_contains($url, "\r")
            || str_contains($url, "\n")
            || str_contains($url, '\\')
            || !str_starts_with($url, '/')
            || str_starts_with($url, '//')) {
            return null;
        }

        return $url;
    }

    private function sameOriginPath(Request $request, string $referer): ?string
    {
        if ($this->localUrl($referer) !== null) {
            return $referer;
        }

        $parts = parse_url($referer);
        if (!is_array($parts)
            || !isset($parts['scheme'], $parts['host'])
            || strcasecmp((string) $parts['scheme'], $request->getScheme()) !== 0
            || strcasecmp((string) $parts['host'], $request->getHost()) !== 0
            || isset($parts['user'], $parts['pass'])) {
            return null;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $refererPort = isset($parts['port'])
            ? (int) $parts['port']
            : ($scheme === 'https' ? 443 : 80);
        $requestPort = $request->getPort();
        $requestPort = is_numeric($requestPort)
            ? (int) $requestPort
            : ($request->isSecure() ? 443 : 80);
        if ($refererPort !== $requestPort) {
            return null;
        }

        $path = (string) ($parts['path'] ?? '/');
        if ($path === '' || !str_starts_with($path, '/') || str_starts_with($path, '//')) {
            $path = '/';
        }

        $query = isset($parts['query']) && $parts['query'] !== ''
            ? '?'.$parts['query']
            : '';

        return $this->localUrl($path.$query);
    }

    private function safeUrl(mixed $url, int $maxLength = 2048): ?string
    {
        if (!is_string($url) || $url === '' || strlen($url) > $maxLength || str_contains($url, "\r") || str_contains($url, "\n")) {
            return null;
        }

        if (str_starts_with($url, '/') && !str_starts_with($url, '//')) {
            return $url;
        }

        return preg_match('/^https?:\/\//i', $url) === 1 ? $url : null;
    }

    private function field(): string
    {
        $field = config('laravel-waf.challenge.altcha.field', 'altcha');

        return is_string($field) && preg_match('/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/', $field) === 1
            ? $field
            : 'altcha';
    }

    /** @param array<string, string> $headers */
    private function unavailable(Request $request, array $headers): Response
    {
        if ($request->expectsJson() || $request->hasHeader('X-Livewire')) {
            return new JsonResponse([
                'message' => 'Challenge verification is temporarily unavailable.',
            ], 503, $headers);
        }

        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response(
            ChallengePage::notice(
                'Verification temporarily unavailable',
                'The browser check cannot be completed right now. Please try again shortly.',
            ),
            503,
            $headers,
        );
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

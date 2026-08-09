<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class AltchaChallengeResponder implements ChallengeResponder
{
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

        $field = $this->field();
        $challengeUrl = $this->safeUrl(config('laravel-waf.challenge.altcha.challenge_url'));
        $returnTo = in_array(strtoupper($request->getMethod()), ['GET', 'HEAD'], true)
            ? ($request->attributes->get('laravel-waf.challenge_return_to') ?: $request->getRequestUri())
            : '/';
        $token = $this->tokens->issueRequest(
            $request->ip() ?: 'unknown',
            $returnTo,
            (int) config('laravel-waf.challenge.request_token_ttl_seconds', 600),
        );
        $verifyUrl = $this->verifyUrl();

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

        if ($challengeUrl === null || $token === null || $verifyUrl === null) {
            return $this->unavailable($headers);
        }

        $widget = $this->widget($challengeUrl, $field);
        $script = $this->script().$this->autoSubmitScript();

        $body = ChallengePage::required($this->title, $this->message, $verifyUrl, $token, $widget, $script);

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

        $display = config('laravel-waf.challenge.altcha.display');
        if (is_string($display) && $display !== '') {
            $attributes['display'] = $display;
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
            .'var fieldName='.$field.';'
            .'var submitted=false;'
            .'var storePayload=function(payload){'
            .'if(payload===undefined||payload===null||payload===""){return false;}'
            .'var value=typeof payload==="string"?payload:JSON.stringify(payload);'
            .'var input=form.querySelector("input[data-laravel-waf-altcha-payload]");'
            .'if(!input){input=document.createElement("input");input.type="hidden";'
            .'input.name=fieldName;input.setAttribute("data-laravel-waf-altcha-payload","");'
            .'form.appendChild(input);}'
            .'input.value=value;return true;'
            .'};'
            .'var submit=function(payload){if(submitted||!storePayload(payload)){return;}'
            .'submitted=true;setTimeout(function(){form.submit();},0);};'
            .'widget.addEventListener("statechange",function(event){'
            .'if(event.detail&&event.detail.state==="verified"){submit(event.detail.payload);}'
            .'});'
            .'widget.addEventListener("verified",function(event){'
            .'if(event.detail){submit(event.detail.payload);}'
            .'});'
            .'});</script>';
    }

    private function verifyUrl(): ?string
    {
        try {
            return $this->safeUrl(route((string) config('laravel-waf.challenge.verify_route')));
        } catch (Throwable) {
            return null;
        }
    }

    private function safeUrl(mixed $url): ?string
    {
        if (!is_string($url) || $url === '' || strlen($url) > 2048 || str_contains($url, "\r") || str_contains($url, "\n")) {
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
    private function unavailable(array $headers): Response
    {
        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response(
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Verification temporarily unavailable</title></head>'
            .'<body><main><h1>Verification temporarily unavailable</h1><p>Please try again shortly.</p></main></body></html>',
            503,
            $headers,
        );
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

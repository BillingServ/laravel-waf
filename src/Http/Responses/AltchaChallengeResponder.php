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

        $title = $this->escape($this->title);
        $message = $this->escape($this->message);
        $action = $this->escape($verifyUrl);
        $token = $this->escape($token);
        $widget = $this->widget($challengeUrl, $field);
        $script = $this->script();

        $body = '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<meta name="viewport" content="width=device-width, initial-scale=1">'
            .'<title>'.$title.'</title>'.$script.'</head><body><main>'
            .'<h1>'.$title.'</h1><p>'.$message.'</p>'
            .'<form method="post" action="'.$action.'" autocomplete="off">'
            .'<input type="hidden" name="_waf_challenge" value="'.$token.'">'
            .$widget
            .'<button type="submit">Continue</button></form>'
            .'<noscript>JavaScript is required to complete this verification.</noscript>'
            .'</main></body></html>';

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

        $auto = config('laravel-waf.challenge.altcha.auto', 'onsubmit');
        if (is_string($auto) && $auto !== '') {
            $attributes['auto'] = $auto;
        }

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

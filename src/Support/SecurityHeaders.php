<?php

namespace BillingServ\LaravelWaf\Support;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class SecurityHeaders
{
    public function apply(Request $request, Response $response): void
    {
        if (!config('laravel-waf.security_headers.enabled', true)) {
            return;
        }

        try {
            $this->setIfMissing($response, 'X-Content-Type-Options', config('laravel-waf.security_headers.x_content_type_options'));
            $this->setIfMissing($response, 'X-Frame-Options', config('laravel-waf.security_headers.x_frame_options'));
            $this->setIfMissing($response, 'Referrer-Policy', config('laravel-waf.security_headers.referrer_policy'));
            $this->setIfMissing($response, 'Permissions-Policy', config('laravel-waf.security_headers.permissions_policy'));
            $this->setIfMissing($response, 'Content-Security-Policy', config('laravel-waf.security_headers.content_security_policy'));

            $hsts = config('laravel-waf.security_headers.hsts', []);
            if ($request->isSecure() && is_array($hsts) && (bool) ($hsts['enabled'] ?? false)) {
                $value = 'max-age='.max(0, min(63072000, (int) ($hsts['max_age'] ?? 31536000)));
                if (($hsts['include_subdomains'] ?? false) === true) {
                    $value .= '; includeSubDomains';
                }
                if (($hsts['preload'] ?? false) === true) {
                    $value .= '; preload';
                }

                $this->setIfMissing($response, 'Strict-Transport-Security', $value);
            }
        } catch (Throwable) {
            // A response header must never break the application response.
        }
    }

    private function setIfMissing(Response $response, string $name, mixed $value): void
    {
        if ($response->headers->has($name) || !is_string($value) || trim($value) === '') {
            return;
        }

        $response->headers->set($name, trim($value));
    }
}

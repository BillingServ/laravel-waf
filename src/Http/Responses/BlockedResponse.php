<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class BlockedResponse
{
    public static function make(
        Request $request,
        int $status = 403,
        bool $includeBlockedFlag = false,
        ?string $scope = null,
        bool $supportLivewire = true,
    ): Response {
        $headers = [
            'Cache-Control' => 'no-store',
            'X-Laravel-Waf-Blocked' => 'true',
        ];

        if ($supportLivewire) {
            $livewire = LivewireResponse::blocked($request, $headers);
            if ($livewire !== null) {
                return $livewire;
            }
        }

        if ($request->expectsJson()) {
            $payload = ['message' => 'Request blocked.'];
            if ($includeBlockedFlag) {
                $payload['blocked'] = true;
            }
            if ($scope !== null) {
                $payload['scope'] = $scope;
            }

            return new JsonResponse($payload, $status, $headers);
        }

        $retryUrl = $request->attributes->get('laravel-waf.challenge_return_to');
        $body = ChallengePage::blocked(
            (string) config('laravel-waf.challenge.blocked_title', 'Request blocked'),
            (string) config('laravel-waf.challenge.blocked_message', 'This request was blocked by the site security policy.'),
            is_string($retryUrl) ? $retryUrl : null,
        );
        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response($body, $status, $headers);
    }
}

<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class DefaultChallengeResponder implements ChallengeResponder
{
    public function __construct(
        private readonly string $title,
        private readonly string $message,
        private readonly int $status = 429,
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
            return $this->failed($request);
        }

        if ($request->expectsJson()) {
            return new JsonResponse([
                'message' => $this->message,
                'challenge' => true,
                'scope' => $scope,
            ], $this->status, $headers);
        }

        $body = ChallengePage::notice($this->title, $this->message);

        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response($body, $this->status, $headers);
    }

    private function failed(Request $request): Response
    {
        $headers = [
            'Cache-Control' => 'no-store',
            'X-Laravel-Waf-Challenge' => 'failed',
        ];

        if ($request->expectsJson()) {
            return new JsonResponse([
                'message' => 'Challenge verification failed.',
                'challenge' => false,
                'verification_failed' => true,
                'scope' => 'test',
            ], 422, $headers);
        }

        $retryUrl = $request->attributes->get('laravel-waf.challenge_return_to');
        $body = ChallengePage::failed(
            (string) config('laravel-waf.challenge.failure_title', 'Verification failed'),
            (string) config('laravel-waf.challenge.failure_message', 'We could not confirm this request. Please try again.'),
            is_string($retryUrl) ? $retryUrl : null,
        );
        $headers['Content-Type'] = 'text/html; charset=UTF-8';

        return new Response($body, 422, $headers);
    }
}

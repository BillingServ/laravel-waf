<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class LivewireResponse
{
    /**
     * Return a Livewire response that renders the blocked state in-place.
     *
     * A blocked IP may already be in an ipset before this response is sent.
     * Rendering the state in the current response avoids a second browser
     * request to the blocked route, which iptables cannot exempt by URI.
     */
    public static function blocked(Request $request, array $headers = [], ?string $requestId = null): ?Response
    {
        if (!self::isUpdateRequest($request)) {
            return null;
        }

        $components = $request->input('components');
        if (is_array($components) && $components !== []) {
            $responses = [];
            foreach ($components as $component) {
                if (!is_array($component) || !is_string($component['snapshot'] ?? null)) {
                    return null;
                }

                $responses[] = [
                    'snapshot' => $component['snapshot'],
                    'effects' => [
                        'html' => self::blockedFragment($component['snapshot'], null, $requestId),
                        'dirty' => [],
                    ],
                ];
            }

            return new JsonResponse([
                'components' => $responses,
                'assets' => [],
            ], 200, $headers);
        }

        $serverMemo = $request->input('serverMemo');
        if (!is_array($serverMemo)) {
            return null;
        }

        return new JsonResponse([
            'effects' => [
                'html' => self::blockedFragment(null, $request, $requestId),
                'dirty' => [],
            ],
            'serverMemo' => $serverMemo,
        ], 200, $headers);
    }

    private static function isUpdateRequest(Request $request): bool
    {
        return $request->hasHeader('X-Livewire');
    }

    private static function blockedFragment(
        ?string $snapshot,
        ?Request $request = null,
        ?string $requestId = null,
    ): string
    {
        $componentId = self::componentId($snapshot);
        if ($componentId === null && $request !== null) {
            $componentId = self::safeComponentId($request->input('fingerprint.id'))
                ?? self::safeComponentId($request->input('serverMemo.id'));
        }

        return ChallengePage::blockedFragment(
            (string) config('laravel-waf.challenge.blocked_title', 'Sorry, you’ve been blocked from viewing this page.'),
            (string) config('laravel-waf.challenge.blocked_message', 'This site uses automated security checks to protect against abusive or malicious traffic. The request matched a rule that prevents it from continuing.'),
            $componentId,
            $requestId,
        );
    }

    private static function componentId(?string $snapshot): ?string
    {
        if ($snapshot === null || $snapshot === '') {
            return null;
        }

        try {
            $decoded = json_decode($snapshot, true, 32, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        return is_array($decoded)
            ? self::safeComponentId($decoded['memo']['id'] ?? null)
            : null;
    }

    private static function safeComponentId(mixed $componentId): ?string
    {
        return is_string($componentId)
            && preg_match('/^[A-Za-z0-9_-]{1,128}$/', $componentId) === 1
            ? $componentId
            : null;
    }
}

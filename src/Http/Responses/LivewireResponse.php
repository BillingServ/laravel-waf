<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class LivewireResponse
{
    /**
     * Return a successful Livewire response that navigates the browser to a
     * top-level challenge page. Rendering the challenge HTML in the update
     * response makes it appear inside the current component or modal.
     */
    public static function challenge(Request $request, string $url, array $headers = []): ?Response
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
                    'effects' => ['redirect' => $url],
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
                'html' => null,
                'dirty' => [],
                'redirect' => $url,
            ],
            'serverMemo' => $serverMemo,
        ], 200, $headers);
    }

    /**
     * Return the Livewire response shape for a top-level blocked-page redirect.
     *
     * Livewire requires a successful JSON response for client-side redirects.
     * The incoming snapshots are returned unchanged so the client can finish
     * the current commit before navigating away.
     */
    public static function blocked(Request $request, array $headers = []): ?Response
    {
        if (!self::isUpdateRequest($request)) {
            return null;
        }

        $url = self::blockedUrl();
        $components = $request->input('components');
        if ($url === null) {
            return null;
        }

        if (is_array($components) && $components !== []) {
            $responses = [];
            foreach ($components as $component) {
                if (!is_array($component) || !is_string($component['snapshot'] ?? null)) {
                    return null;
                }

                $responses[] = [
                    'snapshot' => $component['snapshot'],
                    'effects' => ['redirect' => $url],
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
                'html' => null,
                'dirty' => [],
                'redirect' => $url,
            ],
            'serverMemo' => $serverMemo,
        ], 200, $headers);
    }

    private static function isUpdateRequest(Request $request): bool
    {
        return $request->hasHeader('X-Livewire');
    }

    private static function blockedUrl(): ?string
    {
        try {
            $route = config('laravel-waf.challenge.blocked_route', 'laravel-waf.blocked');
            if (!is_string($route) || $route === '') {
                return null;
            }

            return route($route);
        } catch (Throwable) {
            return null;
        }
    }
}

<?php

return [
    'enabled' => env('LARAVEL_WAF_ENABLED', true),

    'ddos' => [
        'enabled' => env('LARAVEL_WAF_DDOS_ENABLED', true),

        // These are application safety limits. Nginx must still enforce the
        // earlier network and connection limits documented by this package.
        'global' => [
            'max_attempts' => (int) env('LARAVEL_WAF_GLOBAL_MAX_ATTEMPTS', 120),
            'decay_seconds' => (int) env('LARAVEL_WAF_GLOBAL_DECAY_SECONDS', 60),
        ],

        // Keys are route names. The wildcard applies when a route has no
        // explicit policy. Raw URLs are intentionally not used as keys.
        'routes' => [
            '*' => [
                'max_attempts' => (int) env('LARAVEL_WAF_ROUTE_MAX_ATTEMPTS', 60),
                'decay_seconds' => (int) env('LARAVEL_WAF_ROUTE_DECAY_SECONDS', 60),
            ],
        ],

        'mode' => env('LARAVEL_WAF_DDOS_MODE', 'reject'), // reject|challenge
        'status' => 429,
        'fail_mode' => env('LARAVEL_WAF_DDOS_FAIL_MODE', 'open'), // open|closed
        'exempt_routes' => [
            'laravel-waf.metrics',
        ],
        'include_headers' => true,
    ],

    'challenge' => [
        // The first release exposes a challenge boundary. A CAPTCHA provider
        // can be bound to the ChallengeResponder contract later.
        'enabled' => env('LARAVEL_WAF_CHALLENGE_ENABLED', false),
        'title' => 'Additional verification required',
        'message' => 'Please complete the verification before continuing.',
    ],

    'agent' => [
        'enabled' => env('LARAVEL_WAF_AGENT_ENABLED', false),
        'socket' => env('LARAVEL_WAF_AGENT_SOCKET', '/run/laravel-waf/agent.sock'),
        'secret' => env('LARAVEL_WAF_AGENT_SECRET'),
        'timeout_ms' => (int) env('LARAVEL_WAF_AGENT_TIMEOUT_MS', 25),
        'block_ttl_seconds' => (int) env('LARAVEL_WAF_AGENT_BLOCK_TTL_SECONDS', 900),
        'block_cooldown_seconds' => (int) env('LARAVEL_WAF_AGENT_BLOCK_COOLDOWN_SECONDS', 60),
        'auto_block_on_limit' => env('LARAVEL_WAF_AGENT_AUTO_BLOCK', false),
    ],

    'metrics' => [
        'enabled' => env('LARAVEL_WAF_METRICS_ENABLED', false),
        'route' => env('LARAVEL_WAF_METRICS_ROUTE', '_waf/metrics'),
        'middleware' => [],
        'namespace' => 'laravel_waf',
    ],
];

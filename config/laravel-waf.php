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
            'laravel-waf.challenge.verify',
        ],
        'include_headers' => true,
    ],

    'challenge' => [
        'enabled' => env('LARAVEL_WAF_CHALLENGE_ENABLED', false),
        'provider' => env('LARAVEL_WAF_CHALLENGE_PROVIDER', 'default'), // default|altcha
        'title' => 'Additional verification required',
        'message' => 'Please complete the verification before continuing.',
        'path' => env('LARAVEL_WAF_CHALLENGE_PATH', '_waf/challenge/verify'),
        'verify_route' => 'laravel-waf.challenge.verify',
        'cookie_name' => env('LARAVEL_WAF_CHALLENGE_COOKIE', 'laravel_waf_challenge'),
        'cookie_secret' => env('LARAVEL_WAF_CHALLENGE_COOKIE_SECRET'),
        'cookie_ttl_seconds' => (int) env('LARAVEL_WAF_CHALLENGE_COOKIE_TTL', 600),
        'cookie_secure' => env('LARAVEL_WAF_CHALLENGE_COOKIE_SECURE', true),
        'cookie_same_site' => env('LARAVEL_WAF_CHALLENGE_COOKIE_SAME_SITE', 'lax'),
        'request_token_ttl_seconds' => (int) env('LARAVEL_WAF_CHALLENGE_TOKEN_TTL', 600),
        'max_attempts' => (int) env('LARAVEL_WAF_CHALLENGE_MAX_ATTEMPTS', 10),
        'decay_seconds' => (int) env('LARAVEL_WAF_CHALLENGE_DECAY_SECONDS', 60),
        'replay_ttl_seconds' => (int) env('LARAVEL_WAF_CHALLENGE_REPLAY_TTL', 600),

        // A verified browser still receives a bounded rate limit. Passing a
        // challenge must not turn into an unlimited bypass.
        'passed' => [
            'global' => [
                'max_attempts' => (int) env('LARAVEL_WAF_CHALLENGE_PASSED_GLOBAL_MAX_ATTEMPTS', 240),
                'decay_seconds' => (int) env('LARAVEL_WAF_CHALLENGE_PASSED_GLOBAL_DECAY_SECONDS', 60),
            ],
            'routes' => [
                '*' => [
                    'max_attempts' => (int) env('LARAVEL_WAF_CHALLENGE_PASSED_ROUTE_MAX_ATTEMPTS', 120),
                    'decay_seconds' => (int) env('LARAVEL_WAF_CHALLENGE_PASSED_ROUTE_DECAY_SECONDS', 60),
                ],
            ],
        ],

        'altcha' => [
            // Existing bsv211 deployments can keep using ALTCHA_CHALLENGE_URL
            // and ALTCHA_HMAC_KEY. WAF-specific variables take precedence.
            'challenge_url' => env('LARAVEL_WAF_ALTCHA_CHALLENGE_URL', env('ALTCHA_CHALLENGE_URL')),
            'hmac_key' => env('LARAVEL_WAF_ALTCHA_HMAC_KEY', env('ALTCHA_HMAC_KEY')),
            'verification' => env('LARAVEL_WAF_ALTCHA_VERIFICATION', 'solution'), // solution|server_signature
            'field' => env('LARAVEL_WAF_ALTCHA_FIELD', 'altcha'),
            'max_payload_bytes' => (int) env('LARAVEL_WAF_ALTCHA_MAX_PAYLOAD_BYTES', 65536),
            'challenge_attribute' => env('LARAVEL_WAF_ALTCHA_CHALLENGE_ATTRIBUTE', 'challengeurl'), // challengeurl|challenge
            'script_url' => env(
                'LARAVEL_WAF_ALTCHA_SCRIPT_URL',
                'https://cdn.jsdelivr.net/gh/altcha-org/altcha/dist/altcha.min.js',
            ),
            'script_integrity' => env('LARAVEL_WAF_ALTCHA_SCRIPT_INTEGRITY'),
            'hide_logo' => env('LARAVEL_WAF_ALTCHA_HIDE_LOGO', true),
            'auto' => env('LARAVEL_WAF_ALTCHA_AUTO', 'onsubmit'),
            'display' => env('LARAVEL_WAF_ALTCHA_DISPLAY'),
        ],
    ],

    'testing' => [
        // Explicitly opt in before using /protected-route?test.
        'enabled' => env('LARAVEL_WAF_TESTING_ENABLED', false),
        'parameter' => env('LARAVEL_WAF_TESTING_PARAMETER', 'test'),
        'value' => env('LARAVEL_WAF_TESTING_VALUE'),
        'allow_production' => env('LARAVEL_WAF_TESTING_ALLOW_PRODUCTION', false),
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

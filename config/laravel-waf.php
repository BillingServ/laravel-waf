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
            'laravel-waf.blocked',
        ],
        'include_headers' => true,
    ],

    'rules' => [
        'enabled' => env('LARAVEL_WAF_RULES_ENABLED', true),
        'mode' => env('LARAVEL_WAF_RULES_MODE', 'reject'), // reject|challenge|log
        'status' => (int) env('LARAVEL_WAF_RULES_STATUS', 403),
        'fail_mode' => env('LARAVEL_WAF_RULES_FAIL_MODE', 'open'), // open|closed
        'max_findings' => (int) env('LARAVEL_WAF_RULES_MAX_FINDINGS', 3),
        'skip_routes' => [
            'laravel-waf.metrics',
            'laravel-waf.challenge.verify',
            'laravel-waf.blocked',
        ],
        'input' => [
            'path' => true,
            'query' => true,
            'body' => true,
            'route' => true,
            'headers' => false,
            'cookies' => false,
            'max_total_bytes' => (int) env('LARAVEL_WAF_RULES_MAX_INPUT_BYTES', 65536),
            'max_value_bytes' => (int) env('LARAVEL_WAF_RULES_MAX_VALUE_BYTES', 8192),
            'max_values' => (int) env('LARAVEL_WAF_RULES_MAX_VALUES', 256),
            'max_depth' => (int) env('LARAVEL_WAF_RULES_MAX_DEPTH', 5),
        ],
        'categories' => [
            'policy' => [
                'enabled' => env('LARAVEL_WAF_POLICY_RULES_ENABLED', true),
                'action' => env('LARAVEL_WAF_POLICY_ACTION'),
            ],
            'xss' => [
                'enabled' => env('LARAVEL_WAF_XSS_ENABLED', true),
                'action' => env('LARAVEL_WAF_XSS_ACTION'),
                'exclude_fields' => [],
            ],
            'sqli' => [
                'enabled' => env('LARAVEL_WAF_SQLI_ENABLED', true),
                'action' => env('LARAVEL_WAF_SQLI_ACTION'),
                'exclude_fields' => [],
            ],
            'rfi' => [
                'enabled' => env('LARAVEL_WAF_RFI_ENABLED', true),
                'action' => env('LARAVEL_WAF_RFI_ACTION'),
                'exclude_fields' => [],
                'remote_url_fields' => ['file', 'path', 'page', 'include', 'template', 'module', 'resource', 'url'],
                'allowed_remote_hosts' => [],
            ],
            'lfi' => [
                'enabled' => env('LARAVEL_WAF_LFI_ENABLED', true),
                'action' => env('LARAVEL_WAF_LFI_ACTION'),
                'exclude_fields' => [],
            ],
            'geo' => [
                'enabled' => env('LARAVEL_WAF_GEO_ENABLED', false),
                'action' => env('LARAVEL_WAF_GEO_ACTION'),
            ],
            'command' => [
                'enabled' => env('LARAVEL_WAF_COMMAND_ENABLED', true),
                'action' => env('LARAVEL_WAF_COMMAND_ACTION'),
                'exclude_fields' => [],
            ],
            'template' => [
                'enabled' => env('LARAVEL_WAF_TEMPLATE_ENABLED', true),
                'action' => env('LARAVEL_WAF_TEMPLATE_ACTION'),
                'exclude_fields' => [],
            ],
            'nosqli' => [
                'enabled' => env('LARAVEL_WAF_NOSQLI_ENABLED', true),
                'action' => env('LARAVEL_WAF_NOSQLI_ACTION'),
                'exclude_fields' => [],
            ],
            'ldap' => [
                'enabled' => env('LARAVEL_WAF_LDAP_ENABLED', true),
                'action' => env('LARAVEL_WAF_LDAP_ACTION'),
                'exclude_fields' => [],
            ],
            'http' => [
                'enabled' => env('LARAVEL_WAF_HTTP_ENABLED', true),
                'action' => env('LARAVEL_WAF_HTTP_ACTION'),
                'exclude_fields' => [],
            ],
            'ssrf' => [
                'enabled' => env('LARAVEL_WAF_SSRF_ENABLED', true),
                'action' => env('LARAVEL_WAF_SSRF_ACTION'),
                'exclude_fields' => [],
                'url_fields' => [
                    'url', 'uri', 'endpoint', 'callback', 'webhook', 'redirect',
                    'proxy', 'avatar', 'image', 'feed', 'source', 'host', 'domain',
                ],
                'allowed_hosts' => [],
                'allow_private_ips' => false,
            ],
        ],
    ],

    // Route names are the stable key for application-specific request policy.
    // An empty map leaves this feature inactive even when the rule is enabled.
    'policies' => [
        'enabled' => env('LARAVEL_WAF_POLICIES_ENABLED', false),
        'routes' => [],
    ],

    'behavior' => [
        'enabled' => env('LARAVEL_WAF_BEHAVIOR_ENABLED', true),
        'window_seconds' => (int) env('LARAVEL_WAF_BEHAVIOR_WINDOW_SECONDS', 60),
        'thresholds' => [
            '404' => (int) env('LARAVEL_WAF_BEHAVIOR_404_THRESHOLD', 30),
            '405' => (int) env('LARAVEL_WAF_BEHAVIOR_405_THRESHOLD', 20),
            '401' => (int) env('LARAVEL_WAF_BEHAVIOR_401_THRESHOLD', 20),
            '403' => (int) env('LARAVEL_WAF_BEHAVIOR_403_THRESHOLD', 30),
            'client_error' => (int) env('LARAVEL_WAF_BEHAVIOR_CLIENT_ERROR_THRESHOLD', 100),
        ],
        'action' => env('LARAVEL_WAF_BEHAVIOR_ACTION', 'challenge'),
        'alert_cooldown_seconds' => (int) env('LARAVEL_WAF_BEHAVIOR_ALERT_COOLDOWN', 60),
        'skip_routes' => [],
    ],

    'security_headers' => [
        'enabled' => env('LARAVEL_WAF_SECURITY_HEADERS_ENABLED', true),
        'x_content_type_options' => 'nosniff',
        'x_frame_options' => env('LARAVEL_WAF_X_FRAME_OPTIONS', 'SAMEORIGIN'),
        'referrer_policy' => env('LARAVEL_WAF_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        'permissions_policy' => env('LARAVEL_WAF_PERMISSIONS_POLICY'),
        'content_security_policy' => env('LARAVEL_WAF_CONTENT_SECURITY_POLICY'),
        'hsts' => [
            'enabled' => env('LARAVEL_WAF_HSTS_ENABLED', false),
            'max_age' => (int) env('LARAVEL_WAF_HSTS_MAX_AGE', 31536000),
            'include_subdomains' => env('LARAVEL_WAF_HSTS_INCLUDE_SUBDOMAINS', false),
            'preload' => env('LARAVEL_WAF_HSTS_PRELOAD', false),
        ],
    ],

    // This guard is available to outbound HTTP integrations. It is not
    // applied to every Laravel HTTP client call automatically.
    'outbound' => [
        'allowed_schemes' => ['http', 'https'],
        'allowed_hosts' => [],
        'allow_private_ips' => false,
        'resolve_dns' => false,
    ],

    'geo' => [
        'database' => env('LARAVEL_WAF_GEOIP_DATABASE'),
        'allowed_countries' => array_values(array_filter(array_map(
            static fn (string $country): string => strtoupper(trim($country)),
            explode(',', (string) env('LARAVEL_WAF_GEOIP_ALLOWED_COUNTRIES', '')),
        ), static fn (string $country): bool => $country !== '')),
        'denied_countries' => array_values(array_filter(array_map(
            static fn (string $country): string => strtoupper(trim($country)),
            explode(',', (string) env('LARAVEL_WAF_GEOIP_DENIED_COUNTRIES', '')),
        ), static fn (string $country): bool => $country !== '')),
        'unknown' => env('LARAVEL_WAF_GEOIP_UNKNOWN', 'allow'), // allow|reject
    ],

    'login' => [
        'enabled' => env('LARAVEL_WAF_LOGIN_ENABLED', true),
        'field' => env('LARAVEL_WAF_LOGIN_FIELD', 'email'),
        'max_attempts' => (int) env('LARAVEL_WAF_LOGIN_MAX_ATTEMPTS', 5),
        'decay_seconds' => (int) env('LARAVEL_WAF_LOGIN_DECAY_SECONDS', 300),
        'status' => (int) env('LARAVEL_WAF_LOGIN_STATUS', 429),
        'fail_mode' => env('LARAVEL_WAF_LOGIN_FAIL_MODE', 'open'), // open|closed
        'block_after_attempts' => (int) env('LARAVEL_WAF_LOGIN_BLOCK_AFTER', 10),
        'block_ttl_seconds' => (int) env('LARAVEL_WAF_LOGIN_BLOCK_TTL', 900),
        'auto_block' => env('LARAVEL_WAF_LOGIN_AUTO_BLOCK', false),
        'clear_on_login' => env('LARAVEL_WAF_LOGIN_CLEAR_ON_LOGIN', true),
        'guards' => [],
    ],

    'notifications' => [
        'enabled' => env('LARAVEL_WAF_NOTIFICATIONS_ENABLED', false),
        'channels' => array_values(array_filter(array_map(
            static fn (string $channel): string => strtolower(trim($channel)),
            explode(',', (string) env('LARAVEL_WAF_NOTIFICATION_CHANNELS', 'email,slack')),
        ), static fn (string $channel): bool => in_array($channel, ['email', 'slack'], true))),
        'cooldown_seconds' => (int) env('LARAVEL_WAF_NOTIFICATION_COOLDOWN', 300),
        'email' => [
            'to' => array_values(array_filter(array_map(
                static fn (string $recipient): string => trim($recipient),
                explode(',', (string) env('LARAVEL_WAF_NOTIFICATION_EMAIL_TO', '')),
            ), static fn (string $recipient): bool => filter_var($recipient, FILTER_VALIDATE_EMAIL) !== false)),
            'subject' => env('LARAVEL_WAF_NOTIFICATION_EMAIL_SUBJECT', 'Laravel WAF security event'),
        ],
        'slack' => [
            'webhook_url' => env('LARAVEL_WAF_NOTIFICATION_SLACK_WEBHOOK'),
        ],
        'timeout_seconds' => (int) env('LARAVEL_WAF_NOTIFICATION_TIMEOUT', 3),
    ],

    'challenge' => [
        'enabled' => env('LARAVEL_WAF_CHALLENGE_ENABLED', false),
        'provider' => env('LARAVEL_WAF_CHALLENGE_PROVIDER', 'default'), // default|altcha
        'title' => 'Additional verification required',
        'message' => 'Please complete the verification before continuing.',
        'failure_title' => 'Verification failed',
        'failure_message' => 'We could not confirm this request. Please try again.',
        'blocked_title' => 'Request blocked',
        'blocked_message' => 'This request was blocked by the site security policy.',
        'theme' => env('LARAVEL_WAF_CHALLENGE_THEME', 'auto'), // auto|light|dark
        // Optional white-label identity. Nothing is shown when these are empty.
        'brand_name' => env('LARAVEL_WAF_CHALLENGE_BRAND_NAME'),
        'logo_url' => env('LARAVEL_WAF_CHALLENGE_LOGO_URL'),
        'favicon_url' => env('LARAVEL_WAF_CHALLENGE_FAVICON_URL'),
        'path' => env('LARAVEL_WAF_CHALLENGE_PATH', '_waf/challenge/verify'),
        'verify_route' => 'laravel-waf.challenge.verify',
        'blocked_path' => env('LARAVEL_WAF_BLOCKED_PATH', '_waf/blocked'),
        'blocked_route' => 'laravel-waf.blocked',
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
        'auto_block_on_finding' => env('LARAVEL_WAF_AGENT_AUTO_BLOCK_ON_FINDING', false),
    ],

    'metrics' => [
        'enabled' => env('LARAVEL_WAF_METRICS_ENABLED', false),
        'route' => env('LARAVEL_WAF_METRICS_ROUTE', '_waf/metrics'),
        'middleware' => [],
        'namespace' => 'laravel_waf',
    ],
];

# Nginx DDoS baseline

These are starting points, not universal production values. Tune them against normal traffic, server capacity, PHP-FPM capacity, and the application's route mix.

Place the zones in the `http {}` block:

```nginx
limit_req_zone $binary_remote_addr zone=laravel_waf_per_ip:10m rate=10r/s;
limit_req_zone $server_name zone=laravel_waf_per_server:10m rate=1000r/s;
limit_conn_zone $binary_remote_addr zone=laravel_waf_connections:10m;
```

Apply baseline controls in the relevant `server`/`location` blocks:

```nginx
client_max_body_size 10m;
client_header_timeout 10s;
client_body_timeout 10s;
keepalive_timeout 15s;
send_timeout 10s;
limit_req_status 429;
limit_conn_status 429;

location / {
    limit_req zone=laravel_waf_per_server burst=100 nodelay;
    limit_req zone=laravel_waf_per_ip burst=20 nodelay;
    limit_conn laravel_waf_connections 30;

    # Continue with the application's normal Laravel location configuration.
}
```

Use stricter, separate locations or zones for login, search, upload, report-generation, webhook, and challenge endpoints. Serve static assets and the challenge shell directly from Nginx where practical.

Do not use `X-Forwarded-For`, `CF-Connecting-IP`, or another client-supplied header as the limiting key unless Nginx is configured to accept it only from a trusted proxy. With direct Nginx exposure, use the actual remote address.

These controls still operate after traffic reaches the host. Ask the hosting provider about upstream DDoS filtering for volumetric attacks.

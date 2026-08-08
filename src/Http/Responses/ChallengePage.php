<?php

namespace BillingServ\LaravelWaf\Http\Responses;

final class ChallengePage
{
    public static function required(
        string $title,
        string $message,
        string $action,
        string $token,
        string $widget,
        string $script = '',
    ): string {
        $content = self::identity()
            .'<div class="status-mark">'.self::checkIcon().'</div>'
            .'<h1 id="challenge-title">'.self::escape($title).'</h1>'
            .'<p class="lede">'.self::escape($message).'</p>'
            .'<form method="post" action="'.self::escape($action).'" autocomplete="off">'
            .'<input type="hidden" name="_waf_challenge" value="'.self::escape($token).'">'
            .'<div class="widget-shell">'.$widget.'</div>'
            .'<button type="submit">Continue</button>'
            .'</form>'
            .'<noscript><div class="noscript-note">Please enable JavaScript and cookies to continue.</div></noscript>'
            .'<p class="footnote">This security check helps protect this site from automated traffic.</p>';

        return self::document($title, 'required', $content, $script);
    }

    public static function notice(string $title, string $message): string
    {
        $content = self::identity()
            .'<div class="status-mark">'.self::checkIcon().'</div>'
            .'<h1 id="challenge-title">'.self::escape($title).'</h1>'
            .'<p class="lede">'.self::escape($message).'</p>'
            .'<div class="notice-box"><strong>Verification is temporarily unavailable.</strong>'
            .'<span>Please try again shortly.</span></div>'
            .'<p class="footnote">This security check helps protect this site from automated traffic.</p>';

        return self::document($title, 'required', $content);
    }

    public static function failed(
        string $title = 'Verification failed',
        string $message = 'We could not confirm this request. Please try again.',
        ?string $retryUrl = null,
    ): string {
        $retryUrl = self::localUrl($retryUrl);
        $retry = $retryUrl === null
            ? '<p class="retry-help">Please return to the previous page and try again.</p>'
            : '<a class="secondary-action" href="'.self::escape($retryUrl).'">Try again</a>';

        $content = self::identity()
            .'<div class="status-mark status-mark-error">'.self::errorIcon().'</div>'
            .'<h1 id="challenge-title">'.self::escape($title).'</h1>'
            .'<p class="lede">'.self::escape($message).'</p>'
            .'<div class="error-box" role="alert"><strong>Verification could not be completed.</strong>'
            .'<span>The request was not continued.</span></div>'
            .$retry
            .'<p class="footnote">For your protection, no access was granted.</p>';

        return self::document($title, 'failed', $content);
    }

    public static function blocked(
        string $title = 'Request blocked',
        string $message = 'This request was blocked by the site security policy.',
        ?string $retryUrl = null,
    ): string {
        $retryUrl = self::localUrl($retryUrl);
        $retry = $retryUrl === null
            ? ''
            : '<a class="blocked-action" href="'.self::escape($retryUrl).'">Return to the site</a>';

        $content = '<div class="blocked-hero">'
            .self::identity()
            .'<div class="blocked-mark">'.self::blockedIcon().'</div>'
            .'<h1 id="challenge-title">'.self::escape($title).'</h1>'
            .'<p class="lede">'.self::escape($message).'</p>'
            .'</div>'
            .'<div class="blocked-grid">'
            .'<section class="blocked-section"><h2>Why have I been blocked?</h2>'
            .'<p>This site uses automated security checks to protect against abusive or malicious traffic. The request matched a rule that prevents it from continuing.</p></section>'
            .'<section class="blocked-section"><h2>What can I do to resolve this?</h2>'
            .'<p>Return to the previous page and try again. If the problem continues, contact the site owner and include when this page appeared.</p>'
            .$retry
            .'</section>'
            .'</div>';

        return self::document($title, 'blocked', $content);
    }

    public static function blockedFragment(
        string $title = 'Request blocked',
        string $message = 'This request was blocked by the site security policy.',
        ?string $componentId = null,
    ): string {
        $wireId = $componentId === null
            ? ''
            : ' wire:id="'.self::escape($componentId).'"';

        return '<div'.$wireId.' class="laravel-waf-blocked-fragment" role="alert" '
            .'data-laravel-waf-blocked="true" '
            .'style="box-sizing:border-box;width:100%;max-width:760px;margin:0 auto;padding:40px 24px;color:#1f2937;background:#fff;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;text-align:center">'
            .'<div aria-hidden="true" style="width:72px;height:72px;margin:0 auto 20px;border-radius:50%;color:#fff;background:#b42318;font-size:58px;font-weight:300;line-height:68px">×</div>'
            .'<h1 style="margin:0;color:#101828;font-size:24px;font-weight:600;line-height:1.3">'.self::escape($title).'</h1>'
            .'<p style="max-width:520px;margin:10px auto 28px;color:#667085;font-size:15px;line-height:1.55">'.self::escape($message).'</p>'
            .'<div style="display:grid;gap:16px;padding-top:24px;border-top:1px solid #e4e7ec;text-align:left">'
            .'<section><h2 style="margin:0;color:#101828;font-size:18px;font-weight:500;line-height:1.35">Why have I been blocked?</h2>'
            .'<p style="margin:8px 0 0;color:#667085;font-size:13px;line-height:1.6">This site uses automated security checks to protect against abusive or malicious traffic. The request matched a rule that prevents it from continuing.</p></section>'
            .'<section><h2 style="margin:0;color:#101828;font-size:18px;font-weight:500;line-height:1.35">What can I do to resolve this?</h2>'
            .'<p style="margin:8px 0 0;color:#667085;font-size:13px;line-height:1.6">Return to the previous page and try again. If the problem continues, contact the site owner and include when this page appeared.</p></section>'
            .'</div>'
            .'</div>';
    }

    private static function document(string $title, string $state, string $content, string $head = ''): string
    {
        $favicon = self::assetUrl(config('laravel-waf.challenge.favicon_url'));
        $faviconTag = $favicon === null
            ? ''
            : '<link rel="icon" href="'.self::escape($favicon).'">';

        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<meta name="viewport" content="width=device-width, initial-scale=1">'
            .'<meta name="robots" content="noindex,nofollow">'
            .'<meta name="color-scheme" content="light dark">'
            .$faviconTag
            .'<title>'.self::escape($title).'</title>'
            .'<style>'.self::styles().'</style>'.$head.'</head>'
            .'<body class="theme-'.self::theme().' state-'.self::escape($state).'">'
            .'<main class="page-shell"><section class="challenge-card" aria-labelledby="challenge-title">'
            .$content
            .'</section></main></body></html>';
    }

    private static function identity(): string
    {
        $name = self::configuredString('laravel-waf.challenge.brand_name');
        $logo = self::assetUrl(config('laravel-waf.challenge.logo_url'));

        if ($name === null && $logo === null) {
            return '';
        }

        $logoHtml = $logo === null
            ? ''
            : '<img class="identity-logo" src="'.self::escape($logo).'" alt="">';
        $nameHtml = $name === null ? '' : '<span>'.self::escape($name).'</span>';

        return '<div class="identity">'.$logoHtml.$nameHtml.'</div>';
    }

    private static function checkIcon(): string
    {
        return '<svg class="mark-icon" viewBox="0 0 48 48" fill="none" aria-hidden="true">'
            .'<circle cx="24" cy="24" r="24" fill="var(--mark-background)"/>'
            .'<path d="m15 24.5 6 6 12-13" stroke="var(--mark-foreground)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'
            .'</svg>';
    }

    private static function errorIcon(): string
    {
        return '<svg class="mark-icon" viewBox="0 0 48 48" fill="none" aria-hidden="true">'
            .'<circle cx="24" cy="24" r="24" fill="var(--error-mark-background)"/>'
            .'<path d="M24 14v12" stroke="var(--error-mark-foreground)" stroke-width="2.5" stroke-linecap="round"/>'
            .'<circle cx="24" cy="33" r="1.5" fill="var(--error-mark-foreground)"/>'
            .'</svg>';
    }

    private static function blockedIcon(): string
    {
        return '<svg class="blocked-icon" viewBox="0 0 104 104" fill="none" aria-hidden="true">'
            .'<circle cx="52" cy="52" r="52" fill="var(--blocked-mark-background)"/>'
            .'<path d="m31 31 42 42M73 31 31 73" stroke="var(--blocked-mark-foreground)" stroke-width="12" stroke-linecap="square"/>'
            .'</svg>';
    }

    private static function configuredString(string $key): ?string
    {
        $value = config($key);
        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }

    private static function theme(): string
    {
        $theme = self::configuredString('laravel-waf.challenge.theme') ?? 'auto';

        return in_array($theme, ['auto', 'light', 'dark'], true) ? $theme : 'auto';
    }

    private static function localUrl(?string $url): ?string
    {
        $url = self::assetUrl($url);

        return $url !== null && str_starts_with($url, '/') && !str_starts_with($url, '//')
            ? $url
            : null;
    }

    private static function assetUrl(mixed $url): ?string
    {
        if (!is_string($url) || $url === '' || strlen($url) > 2048 || str_contains($url, "\r") || str_contains($url, "\n")) {
            return null;
        }

        if (str_starts_with($url, '/') && !str_starts_with($url, '//')) {
            return $url;
        }

        return preg_match('/^https?:\/\//i', $url) === 1 ? $url : null;
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function styles(): string
    {
        return <<<'CSS'
:root {
    --background: #f5f6f8;
    --surface: #ffffff;
    --text: #1f2937;
    --muted: #667085;
    --border: #e4e7ec;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --error: #b42318;
    --error-background: #fef3f2;
    --mark-background: #e8f1ff;
    --mark-foreground: #2563eb;
    --error-mark-background: #fdecec;
    --error-mark-foreground: #b42318;
    --blocked-mark-background: #b42318;
    --blocked-mark-foreground: #ffffff;
}

* { box-sizing: border-box; }

html, body { min-height: 100%; }

body {
    display: flex;
    min-height: 100svh;
    margin: 0;
    color: var(--text);
    background: var(--background);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    -webkit-font-smoothing: antialiased;
}

.page-shell {
    display: flex;
    width: 100%;
    min-height: 100svh;
    align-items: center;
    justify-content: center;
    padding: 32px 16px;
}

.challenge-card {
    width: 100%;
    max-width: 520px;
    padding: 40px 44px 36px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--surface);
    box-shadow: 0 4px 24px rgba(16, 24, 40, .07);
    text-align: center;
}

.identity {
    display: inline-flex;
    min-height: 28px;
    align-items: center;
    justify-content: center;
    gap: 10px;
    margin-bottom: 28px;
    color: #344054;
    font-size: 15px;
    font-weight: 600;
}

.identity-logo {
    display: block;
    width: auto;
    max-width: 180px;
    height: 28px;
    object-fit: contain;
}

.status-mark { width: 48px; height: 48px; margin: 0 auto 20px; }
.mark-icon { display: block; width: 48px; height: 48px; }

.blocked-hero { padding: 0 48px 44px; text-align: center; }
.blocked-mark { width: 104px; height: 104px; margin: 0 auto 28px; }
.blocked-icon { display: block; width: 104px; height: 104px; }
.state-blocked .challenge-card { max-width: 760px; padding: 56px 0 0; }

h1 {
    margin: 0;
    color: #101828;
    font-size: 24px;
    font-weight: 600;
    letter-spacing: -.02em;
    line-height: 1.3;
}

.lede {
    max-width: 420px;
    margin: 10px auto 0;
    color: var(--muted);
    font-size: 15px;
    line-height: 1.55;
}

form { margin-top: 26px; }

.widget-shell {
    display: flex;
    width: 100%;
    min-height: 65px;
    align-items: center;
    justify-content: center;
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #fcfcfd;
    overflow: hidden;
    text-align: center;
}

altcha-widget {
    display: block;
    width: 100%;
    max-width: none;
    min-width: 0;
    margin: 0;
}

button, .secondary-action {
    display: inline-flex;
    width: 100%;
    min-height: 44px;
    align-items: center;
    justify-content: center;
    border: 0;
    border-radius: 7px;
    font: inherit;
    font-size: 14px;
    font-weight: 600;
    text-decoration: none;
}

button {
    margin-top: 14px;
    cursor: pointer;
    color: #ffffff;
    background: var(--accent);
    transition: background-color .15s ease;
}

button:hover { background: var(--accent-hover); }
button:focus-visible, .secondary-action:focus-visible { outline: 3px solid rgba(37, 99, 235, .25); outline-offset: 2px; }

.noscript-note {
    margin-top: 16px;
    padding: 10px 12px;
    border: 1px solid #fedf89;
    border-radius: 7px;
    color: #7a2e0e;
    background: #fffaeb;
    font-size: 13px;
    line-height: 1.45;
    text-align: left;
}

.notice-box, .error-box {
    display: grid;
    gap: 4px;
    margin-top: 26px;
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #f9fafb;
    text-align: left;
}

.notice-box strong, .error-box strong { color: #344054; font-size: 13px; font-weight: 600; }
.notice-box span, .error-box span { color: var(--muted); font-size: 13px; line-height: 1.45; }

.error-box { border-color: #fecdca; background: var(--error-background); }
.error-box strong, .error-box span { color: var(--error); }

.secondary-action {
    margin-top: 20px;
    color: #ffffff;
    background: var(--accent);
    transition: background-color .15s ease;
}

.secondary-action:hover { background: var(--accent-hover); }

.retry-help {
    margin: 20px 0 0;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.5;
}

.footnote {
    margin: 24px 0 0;
    color: #98a2b3;
    font-size: 12px;
    line-height: 1.5;
}

.blocked-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    border-top: 1px solid var(--border);
    text-align: left;
}

.blocked-section { padding: 28px 32px 30px; }
.blocked-section + .blocked-section { border-left: 1px solid var(--border); }

.blocked-section h2 {
    margin: 0;
    color: #101828;
    font-size: 18px;
    font-weight: 500;
    letter-spacing: -.015em;
    line-height: 1.35;
}

.blocked-section p {
    margin: 12px 0 0;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.6;
}

.blocked-action {
    display: inline-block;
    margin-top: 16px;
    color: var(--accent);
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
}

.blocked-action:hover { color: var(--accent-hover); text-decoration: underline; }

body.theme-dark {
    --background: #101828;
    --surface: #1d2939;
    --text: #f2f4f7;
    --muted: #98a2b3;
    --border: #344054;
    --accent: #84adff;
    --accent-hover: #a6c3ff;
    --error: #fda29b;
    --error-background: #3a1f24;
    --mark-background: #243b68;
    --mark-foreground: #a6c3ff;
    --error-mark-background: #6d2727;
    --error-mark-foreground: #fda29b;
    --blocked-mark-background: #c43232;
    --blocked-mark-foreground: #ffffff;
}

body.theme-dark h1, body.theme-dark .blocked-section h2 { color: #f9fafb; }
body.theme-dark .identity { color: #eaecf0; }
body.theme-dark .widget-shell { background: #101828; }
body.theme-dark .notice-box { background: #182230; }
body.theme-dark .notice-box strong { color: #eaecf0; }
body.theme-dark .error-box { border-color: #6d2727; }
body.theme-dark .blocked-action { color: #a6c3ff; }
body.theme-dark button, body.theme-dark .secondary-action { color: #101828; }

@media (prefers-color-scheme: dark) {
    body.theme-auto {
        --background: #101828;
        --surface: #1d2939;
        --text: #f2f4f7;
        --muted: #98a2b3;
        --border: #344054;
        --accent: #84adff;
        --accent-hover: #a6c3ff;
        --error: #fda29b;
        --error-background: #3a1f24;
        --mark-background: #243b68;
        --mark-foreground: #a6c3ff;
        --error-mark-background: #6d2727;
        --error-mark-foreground: #fda29b;
        --blocked-mark-background: #c43232;
        --blocked-mark-foreground: #ffffff;
    }

    body.theme-auto h1, body.theme-auto .blocked-section h2 { color: #f9fafb; }
    body.theme-auto .identity { color: #eaecf0; }
    body.theme-auto .widget-shell { background: #101828; }
    body.theme-auto .notice-box { background: #182230; }
    body.theme-auto .notice-box strong { color: #eaecf0; }
    body.theme-auto .error-box { border-color: #6d2727; }
    body.theme-auto .blocked-action { color: #a6c3ff; }
    body.theme-auto button, body.theme-auto .secondary-action { color: #101828; }
}

@media (max-width: 480px) {
    .challenge-card { padding: 32px 24px 28px; }
    .state-blocked .challenge-card { padding: 40px 0 0; }
    .blocked-hero { padding: 0 24px 36px; }
    .blocked-grid { grid-template-columns: 1fr; }
    .blocked-section { padding: 24px; }
    .blocked-section + .blocked-section { border-top: 1px solid var(--border); border-left: 0; }
}

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { transition-duration: .01ms !important; }
}
CSS;
    }
}

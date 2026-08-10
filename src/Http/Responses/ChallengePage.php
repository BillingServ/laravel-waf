<?php

namespace BillingServ\LaravelWaf\Http\Responses;

use BillingServ\LaravelWaf\Support\RequestId;

final class ChallengePage
{
    public static function required(
        string $title,
        string $message,
        string $action,
        string $token,
        string $widget,
        string $script = '',
        bool $automatic = false,
        ?string $requestId = null,
    ): string {
        $formClass = $automatic
            ? 'verification-form is-automatic'
            : 'verification-form';
        $statusTitle = $automatic
            ? 'Checking your browser'
            : $title;
        $statusDetail = $automatic
            ? 'This usually takes only a few seconds.'
            : $message;
        $widgetAttributes = $automatic
            ? ' aria-hidden="true" data-altcha-visibility="concealed"'
            : '';
        $actionControl = $automatic
            ? '<p class="verification-fallback" data-verification-fallback hidden>'
                .'This is taking longer than expected. '
                .'<button class="verification-retry" type="button">Reload the page</button> to try again.</p>'
            : '<button class="verification-submit" type="submit">Continue</button>';
        $guidance = $automatic
            ? 'This check is automatic. You will continue as soon as it is complete.'
            : 'Complete the verification below to continue.';
        $requestId = RequestId::normalize($requestId);

        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<meta name="viewport" content="width=device-width, initial-scale=1">'
            .'<meta name="robots" content="noindex,nofollow">'
            .'<meta name="color-scheme" content="dark">'
            .'<title>Checking your browser</title>'
            .'<style>'.self::verificationStyles().'</style>'.$script.'</head>'
            .'<body data-page-state="required"><main class="verification-main">'
            .'<div class="verification-layout"><div class="verification-indicator">'
            .self::spinner().'</div>'
            .'<div class="verification-content" role="status" aria-live="polite" aria-atomic="true">'
            .'<h1 data-verification-label>'.self::escape($statusTitle).'</h1>'
            .'<p class="verification-lede" data-verification-detail>'.self::escape($statusDetail).'</p>'
            .'<p class="verification-detail" data-verification-guidance>'.self::escape($guidance).'</p>'
            .'<form class="'.$formClass.'" method="post" action="'.self::escape($action).'" autocomplete="off" '
            .'data-verification-state="starting">'
            .'<input type="hidden" name="_waf_challenge" value="'.self::escape($token).'">'
            .'<div class="widget-shell"'.$widgetAttributes.'>'.$widget.'</div>'
            .$actionControl
            .'</form>'
            .'<noscript><p class="verification-fallback">JavaScript is required to complete this check. '
            .'Enable it in your browser settings and reload the page.</p></noscript>'
            .'</div></div></main><footer class="verification-footer">'
            .'<p class="request-id">Request ID: <b>'.self::escape($requestId).'</b></p>'
            .'<p class="attribution">Performance &amp; security by '
            .'<a href="https://www.billingserv.com">BillingServ</a></p>'
            .'</footer></body></html>';
    }

    public static function notice(string $title, string $message): string
    {
        $content = self::header('Service unavailable', true)
            .'<div class="page-content">'
            .'<div class="state-icon danger-icon" aria-hidden="true">'.self::noticeIcon().'</div>'
            .'<p class="state-label danger-label">Service unavailable</p>'
            .'<h1 id="challenge-title">'.self::escape($title).'</h1>'
            .'<p class="lede">'.self::escape($message).'</p>'
            .'<div class="message-box"><strong>Please try again shortly.</strong>'
            .'<span>No access was granted while the check was unavailable.</span></div>'
            .'</div>'
            .self::footer('Protected by site security', 'Error 503');

        return self::document($title, 'notice', $content);
    }

    public static function failed(
        string $title = 'Verification failed',
        string $message = 'We could not confirm this request. Please try again.',
        ?string $retryUrl = null,
    ): string {
        $retryUrl = self::localUrl($retryUrl);
        $retry = $retryUrl === null
            ? '<p class="retry-help">Return to the previous page and start the verification again.</p>'
            : '<a class="secondary-action" href="'.self::escape($retryUrl).'">Try verification again</a>';

        $content = self::header('Verification unsuccessful', true)
            .'<div class="page-content">'
            .'<div class="state-icon danger-icon" aria-hidden="true">'.self::noticeIcon().'</div>'
            .'<p class="state-label danger-label">Verification unsuccessful</p>'
            .'<h1 id="challenge-title">'.self::escape($title).'</h1>'
            .'<p class="lede">'.self::escape($message).'</p>'
            .'<div class="message-box" role="alert"><strong>The request was not continued.</strong>'
            .'<span>Your browser may have taken too long or returned an invalid response.</span></div>'
            .$retry
            .'</div>'
            .self::footer('Protected by site security', 'Error 422');

        return self::document($title, 'failed', $content);
    }

    public static function blocked(
        string $title = 'Sorry, you’ve been blocked from viewing this page.',
        string $message = 'This site uses automated security checks to protect against abusive or malicious traffic. The request matched a rule that prevents it from continuing.',
        ?string $retryUrl = null,
        ?string $requestId = null,
    ): string {
        $homeUrl = self::localUrl($retryUrl) ?? '/';
        $requestId = RequestId::normalize($requestId);

        $template = self::replaceBlockedSection(self::blockedTemplate(), 'TITLE', self::escape($title));
        $template = self::replaceBlockedSection($template, 'MESSAGE', self::escape($message));

        return strtr($template, [
            '@@BLOCKED_HOME_URL@@' => self::escape($homeUrl),
            '@@BLOCKED_REQUEST_ID@@' => self::escape($requestId),
        ]);
    }

    public static function blockedFragment(
        string $title = 'Sorry, you’ve been blocked from viewing this page.',
        string $message = 'This site uses automated security checks to protect against abusive or malicious traffic. The request matched a rule that prevents it from continuing.',
        ?string $componentId = null,
        ?string $requestId = null,
    ): string {
        $wireId = $componentId === null
            ? ''
            : ' wire:id="'.self::escape($componentId).'"';
        $requestId = RequestId::normalize($requestId);

        return '<div'.$wireId.' class="security-blocked-fragment" role="alert" '
            .'data-request-blocked="true" '
            .'style="box-sizing:border-box;width:100%;max-width:880px;margin:24px auto;color:#e9eef6;'
            .'background:#080d15;border:1px solid rgba(255,255,255,.075);font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Arial,sans-serif;text-align:left">'
            .'<div style="display:flex;flex-wrap:wrap;align-items:flex-start;gap:28px 48px;padding:44px 36px">'
            .'<p aria-hidden="true" style="margin:0;color:#edf2fa;font-size:72px;font-weight:700;line-height:.82;letter-spacing:-.045em">403</p>'
            .'<div style="min-width:0;flex:1 1 300px">'
            .'<h1 style="max-width:21ch;margin:0 0 26px;color:#e9eef6;font-size:25px;font-weight:600;letter-spacing:-.015em;line-height:1.34">'
            .self::escape($title).'</h1>'
            .'<section><strong style="display:block;margin-bottom:5px;color:#e9eef6;font-size:15px">Why have I been blocked?</strong>'
            .'<p style="max-width:56ch;margin:0;color:#8994a8;font-size:15px;line-height:1.65">'.self::escape($message).'</p></section>'
            .'<section style="margin-top:22px"><strong style="display:block;margin-bottom:5px;color:#e9eef6;font-size:15px">What can I do to resolve this?</strong>'
            .'<p style="max-width:56ch;margin:0;color:#8994a8;font-size:15px;line-height:1.65">Return to the previous page and try again. If the problem continues, contact the site owner and include the request ID below.</p></section>'
            .'</div></div>'
            .'<div style="padding:18px 28px 20px;border-top:1px solid rgba(255,255,255,.075);text-align:center">'
            .'<p style="margin:0;color:#8994a8;font-size:13px">Request ID: <b style="color:#e9eef6;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-weight:500">'
            .self::escape($requestId).'</b></p>'
            .'<p style="margin:6px 0 0;color:#5a6478;font-size:12px">Performance &amp; security by '
            .'<a href="https://www.billingserv.com" style="color:#74abff;text-decoration:none">BillingServ</a></p>'
            .'</div></div>';
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
            .'<main class="page-shell"><section class="challenge-card" data-page-state="'.self::escape($state).'" '
            .'aria-labelledby="challenge-title">'
            .$content
            .'</section></main></body></html>';
    }

    private static function header(string $status, bool $danger = false): string
    {
        $identity = self::identity();
        if ($identity === '') {
            $identity = '<div class="identity identity-default"><span class="identity-symbol" aria-hidden="true">'
                .self::brandIcon().'</span><span>Site security</span></div>';
        }

        return '<header class="security-header">'.$identity
            .'<div class="security-reference'.($danger ? ' is-danger' : '').'">'
            .'<span class="reference-dot" aria-hidden="true"></span>'
            .self::escape($status).'</div></header>';
    }

    private static function footer(string $left, string $right): string
    {
        return '<footer class="card-footer"><span>'.self::escape($left).'</span>'
            .'<span>'.self::escape($right).'</span></footer>';
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

    private static function brandIcon(): string
    {
        return '<svg class="brand-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
            .'<path d="M12 3.25 19 6.2v4.55c0 4.5-2.78 8.37-7 10-4.22-1.63-7-5.5-7-10V6.2l7-2.95Z" '
            .'stroke="currentColor" stroke-width="1.75" stroke-linejoin="round"/></svg>';
    }

    private static function spinner(): string
    {
        return '<svg class="verification-spinner" viewBox="0 0 48 48" width="96" height="96" '
            .'aria-hidden="true" focusable="false">'
            .'<circle class="spinner-track" cx="24" cy="24" r="21" fill="none" stroke-width="2.5"/>'
            .'<circle class="spinner-arc" cx="24" cy="24" r="21" fill="none" stroke-width="2.5" '
            .'stroke-linecap="round" stroke-dasharray="34 98"/></svg>';
    }

    private static function noticeIcon(): string
    {
        return '<svg class="state-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
            .'<circle cx="12" cy="12" r="9.25" stroke="currentColor" stroke-width="1.6"/>'
            .'<path d="M12 7.5v5.25M12 16.5h.01" stroke="currentColor" stroke-width="1.8" '
            .'stroke-linecap="round"/></svg>';
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

    private static function verificationStyles(): string
    {
        return <<<'CSS'
:root {
    --text: #e9eef6;
    --muted: #8994a8;
    --dim: #5a6478;
    --line: rgba(255, 255, 255, .075);
    --blue: #74abff;
    --blue-dim: #3e6db8;
}

* { box-sizing: border-box; }
[hidden] { display: none !important; }

html { background-color: #080d15; }

body {
    display: flex;
    min-height: 100vh;
    min-height: 100dvh;
    flex-direction: column;
    margin: 0;
    color: var(--text);
    background-color: #080d15;
    background-image:
        radial-gradient(1100px 560px at 50% -12%, rgba(56, 96, 160, .10), rgba(56, 96, 160, 0) 70%),
        linear-gradient(180deg, #0a101b 0%, #080c13 100%);
    background-repeat: no-repeat;
    background-attachment: fixed;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 15px;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
}

.verification-main {
    display: flex;
    flex: 1 1 auto;
    align-items: center;
    justify-content: center;
    padding: 64px 32px;
}

.verification-layout {
    display: grid;
    width: 100%;
    max-width: 880px;
    grid-template-columns: auto minmax(0, 1fr);
    align-items: start;
    gap: 64px;
}

.verification-indicator {
    display: flex;
    width: 108px;
    justify-content: center;
    padding-top: 6px;
}

.verification-spinner { display: block; }
.spinner-track { stroke: rgba(255, 255, 255, .09); }

.spinner-arc {
    stroke: var(--blue);
    transform-origin: 50% 50%;
    animation: verification-spin 1.1s linear infinite;
}

.verification-content { padding-top: 4px; }

.verification-content h1 {
    margin: 0 0 14px;
    font-size: clamp(21px, 3.2vw, 27px);
    font-weight: 600;
    letter-spacing: -.015em;
    line-height: 1.34;
}

.verification-lede {
    margin: 0;
    color: var(--text);
    font-size: 16px;
}

.verification-detail {
    max-width: 56ch;
    margin: 18px 0 0;
    color: var(--muted);
    line-height: 1.65;
}

.verification-form { margin: 0; }

.widget-shell {
    width: 100%;
    max-width: 560px;
    margin-top: 22px;
    padding: 12px;
    overflow: hidden;
    border: 1px solid var(--line);
    background: rgba(255, 255, 255, .025);
}

.verification-form.is-automatic .widget-shell { display: none; }
.verification-form.is-automatic.requires-interaction .widget-shell { display: block; }

altcha-widget {
    display: block;
    width: 100%;
    max-width: none;
    min-width: 0;
    margin: 0;
}

.verification-fallback {
    max-width: 56ch;
    margin: 22px 0 0;
    padding-top: 18px;
    border-top: 1px solid var(--line);
    color: var(--muted);
}

.verification-retry {
    display: inline;
    margin: 0;
    padding: 0;
    border: 0;
    color: var(--blue);
    background: transparent;
    cursor: pointer;
    font: inherit;
    text-decoration: none;
}

.verification-retry:hover {
    text-decoration: underline;
    text-underline-offset: 3px;
}

.verification-submit {
    display: inline-flex;
    min-height: 42px;
    align-items: center;
    justify-content: center;
    margin-top: 18px;
    padding: 0 22px;
    border: 1px solid var(--blue-dim);
    border-radius: 3px;
    color: var(--text);
    background: rgba(62, 109, 184, .16);
    cursor: pointer;
    font: inherit;
    font-weight: 600;
}

.verification-submit:hover { background: rgba(62, 109, 184, .28); }

.verification-footer {
    flex: 0 0 auto;
    padding: 22px 32px 26px;
    border-top: 1px solid var(--line);
    text-align: center;
}

.request-id {
    margin: 0;
    color: var(--muted);
    font-size: 14px;
}

.request-id b {
    color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
    font-weight: 500;
    letter-spacing: .02em;
    overflow-wrap: anywhere;
}

.attribution {
    margin: 7px 0 0;
    color: var(--dim);
    font-size: 13px;
}

.attribution a {
    color: var(--blue);
    text-decoration: none;
}

.attribution a:hover {
    text-decoration: underline;
    text-underline-offset: 3px;
}

:focus-visible {
    border-radius: 2px;
    outline: 2px solid var(--blue);
    outline-offset: 3px;
}

body[data-verification-state="verified"] .spinner-arc {
    animation-duration: .45s;
}

@media (prefers-reduced-motion: reduce) {
    .spinner-arc { animation-duration: 3.2s; }
}

@media (max-width: 700px) {
    .verification-main { padding: 48px 24px; }
    .verification-layout { grid-template-columns: 1fr; gap: 26px; }
    .verification-indicator { width: auto; justify-content: flex-start; padding-top: 0; }
    .verification-spinner { width: 68px; height: 68px; }
    .verification-content { padding-top: 0; }
    .verification-footer { padding: 20px 24px 24px; }
}

@keyframes verification-spin {
    to { transform: rotate(360deg); }
}
CSS;
    }

    private static function blockedTemplate(): string
    {
        $template = @file_get_contents(dirname(__DIR__, 3).'/resources/pages/blocked.html');
        $tokens = [
            '<!--@@BLOCKED_TITLE_START@@-->',
            '<!--@@BLOCKED_TITLE_END@@-->',
            '<!--@@BLOCKED_MESSAGE_START@@-->',
            '<!--@@BLOCKED_MESSAGE_END@@-->',
            '@@BLOCKED_HOME_URL@@',
            '@@BLOCKED_REQUEST_ID@@',
        ];

        if (is_string($template)) {
            foreach ($tokens as $token) {
                if (!str_contains($template, $token)) {
                    $template = null;
                    break;
                }
            }

            if ($template !== null) {
                return $template;
            }
        }

        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<meta name="viewport" content="width=device-width,initial-scale=1">'
            .'<meta name="robots" content="noindex,nofollow"><title>Request blocked</title></head>'
            .'<body><main><h1><!--@@BLOCKED_TITLE_START@@-->Request blocked'
            .'<!--@@BLOCKED_TITLE_END@@--></h1>'
            .'<p><!--@@BLOCKED_MESSAGE_START@@-->This request was blocked by the site security policy.'
            .'<!--@@BLOCKED_MESSAGE_END@@--></p>'
            .'<p>Request ID: <b>@@BLOCKED_REQUEST_ID@@</b></p>'
            .'<p><a href="@@BLOCKED_HOME_URL@@">Back to homepage</a></p></main></body></html>';
    }

    private static function replaceBlockedSection(string $template, string $name, string $replacement): string
    {
        $start = '<!--@@BLOCKED_'.$name.'_START@@-->';
        $end = '<!--@@BLOCKED_'.$name.'_END@@-->';
        $startAt = strpos($template, $start);
        if ($startAt === false) {
            return $template;
        }

        $endAt = strpos($template, $end, $startAt + strlen($start));
        if ($endAt === false) {
            return $template;
        }

        return substr($template, 0, $startAt)
            .$replacement
            .substr($template, $endAt + strlen($end));
    }

    private static function styles(): string
    {
        return <<<'CSS'
:root {
    --page-bg: #f4f5f7;
    --surface: #ffffff;
    --text: #202124;
    --muted: #5f6368;
    --border: #dfe3e8;
    --subtle: #f6f7f8;
    --accent: #245da6;
    --accent-soft: #edf4fc;
    --danger: #b42318;
    --danger-soft: #fdf0ee;
    --button: #25313d;
    --button-hover: #17212b;
    --button-text: #ffffff;
    --focus: #3977c4;
    --shadow: rgba(16, 24, 40, .08);
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

* { box-sizing: border-box; }
[hidden] { display: none !important; }
html, body { min-height: 100%; }

body {
    min-height: 100svh;
    margin: 0;
    color: var(--text);
    background: var(--page-bg);
    font-family: var(--font);
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
}

.page-shell {
    display: grid;
    width: 100%;
    min-height: 100svh;
    place-items: center;
    padding: 40px 20px;
}

.challenge-card {
    width: min(100%, 660px);
    overflow: hidden;
    border: 1px solid var(--border);
    border-top: 3px solid var(--accent);
    border-radius: 10px;
    background: var(--surface);
    box-shadow: 0 18px 48px var(--shadow);
}

.state-failed .challenge-card,
.state-notice .challenge-card {
    border-top-color: var(--danger);
}

.security-header {
    display: flex;
    min-height: 66px;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 16px 28px;
    border-bottom: 1px solid var(--border);
}

.identity {
    display: inline-flex;
    min-width: 0;
    align-items: center;
    gap: 10px;
    color: var(--text);
    font-size: 14px;
    font-weight: 650;
}

.identity-logo {
    display: block;
    width: auto;
    max-width: 180px;
    height: 28px;
    object-fit: contain;
}

.identity-symbol {
    display: grid;
    width: 28px;
    height: 28px;
    place-items: center;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 7px;
    background: var(--subtle);
}

.brand-icon {
    display: block;
    width: 17px;
    height: 17px;
}

.security-reference {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 550;
    white-space: nowrap;
}

.reference-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--accent);
}

.security-reference.is-danger .reference-dot { background: var(--danger); }

.page-content { padding: 48px 52px 52px; }

.state-icon {
    display: grid;
    width: 48px;
    height: 48px;
    place-items: center;
    margin-bottom: 20px;
    color: var(--accent);
    border: 1px solid #d5e3f4;
    border-radius: 50%;
    background: var(--accent-soft);
}

.state-icon.danger-icon {
    color: var(--danger);
    border-color: #f2cec9;
    background: var(--danger-soft);
}

.state-svg {
    display: block;
    width: 25px;
    height: 25px;
}

.state-label {
    margin: 0 0 10px;
    color: var(--accent);
    font-size: 13px;
    font-weight: 650;
}

.state-label.danger-label { color: var(--danger); }

h1 {
    max-width: 560px;
    margin: 0;
    color: var(--text);
    font-size: clamp(30px, 5vw, 38px);
    font-weight: 680;
    letter-spacing: -.025em;
    line-height: 1.18;
}

.lede {
    max-width: 560px;
    margin: 16px 0 0;
    color: var(--muted);
    font-size: 16px;
    line-height: 1.65;
}

.secondary-action {
    display: inline-flex;
    min-height: 44px;
    align-items: center;
    justify-content: center;
    margin-top: 16px;
    padding: 0 20px;
    border: 0;
    border-radius: 7px;
    color: var(--button-text);
    background: var(--button);
    font-size: 14px;
    font-weight: 650;
    text-decoration: none;
    transition: background-color .15s ease;
}

.secondary-action:hover { background: var(--button-hover); }

.secondary-action:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 3px;
}

.message-box {
    display: grid;
    gap: 4px;
    margin-top: 24px;
    padding: 15px 16px;
    border: 1px solid #f2cec9;
    border-radius: 8px;
    color: var(--muted);
    background: var(--danger-soft);
    font-size: 13px;
    line-height: 1.5;
}

.message-box strong { color: var(--text); }

.retry-help {
    margin: 22px 0 0;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.55;
}

.card-footer {
    display: flex;
    min-height: 52px;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    padding: 14px 28px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    background: var(--subtle);
    font-size: 11px;
}

body.theme-dark {
    --page-bg: #111417;
    --surface: #1b1f23;
    --text: #f1f3f4;
    --muted: #a9b0b7;
    --border: #343a40;
    --subtle: #22272c;
    --accent: #82afe8;
    --accent-soft: #1e3046;
    --danger: #f38b82;
    --danger-soft: #3a2322;
    --button: #e5e9ed;
    --button-hover: #ffffff;
    --button-text: #202124;
    --focus: #82afe8;
    --shadow: rgba(0, 0, 0, .28);
}

body.theme-dark .state-icon { border-color: #315173; }
body.theme-dark .state-icon.danger-icon,
body.theme-dark .message-box { border-color: #653b38; }

@media (prefers-color-scheme: dark) {
    body.theme-auto {
        --page-bg: #111417;
        --surface: #1b1f23;
        --text: #f1f3f4;
        --muted: #a9b0b7;
        --border: #343a40;
        --subtle: #22272c;
        --accent: #82afe8;
        --accent-soft: #1e3046;
        --danger: #f38b82;
        --danger-soft: #3a2322;
        --button: #e5e9ed;
        --button-hover: #ffffff;
        --button-text: #202124;
        --focus: #82afe8;
        --shadow: rgba(0, 0, 0, .28);
    }

    body.theme-auto .state-icon { border-color: #315173; }
    body.theme-auto .state-icon.danger-icon,
    body.theme-auto .message-box { border-color: #653b38; }
}

@media (max-width: 600px) {
    .page-shell { padding: 18px 12px; }
    .challenge-card { border-radius: 8px; }
    .security-header { min-height: 60px; padding: 14px 20px; }
    .security-reference { font-size: 11px; }
    .page-content { padding: 38px 28px 42px; }
    .card-footer {
        align-items: flex-start;
        flex-direction: column;
        gap: 4px;
        padding: 14px 20px;
    }
}

@media (max-width: 380px) {
    .identity span:last-child { display: none; }
    .page-content { padding-right: 22px; padding-left: 22px; }
}

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: .01ms !important;
    }
}

CSS;
    }
}

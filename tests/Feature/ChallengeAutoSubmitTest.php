<?php

namespace BillingServ\LaravelWaf\Tests\Feature;

use BillingServ\LaravelWaf\Contracts\ChallengeResponder;
use BillingServ\LaravelWaf\Tests\TestCase;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Process\Process;

final class ChallengeAutoSubmitTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('laravel-waf.challenge.provider', 'altcha');
        $app['config']->set('laravel-waf.challenge.altcha.challenge_url', 'https://example.com/challenge');
        $app['config']->set('laravel-waf.challenge.altcha.auto_submit', true);
    }

    public static function widgetTimings(): array
    {
        return [
            'verified before page load' => ['verified'],
            'page loaded before initialization' => ['complete'],
            'widget loads after initialization' => ['late'],
            'ordinary verification events' => ['events'],
            'retry after failure' => ['retry'],
        ];
    }

    #[DataProvider('widgetTimings')]
    public function test_verification_continues_without_reloading(string $scenario): void
    {
        $response = app(ChallengeResponder::class)->respond(Request::create('/login'), 60, 'adaptive');
        preg_match('~<script>(.*?)</script>~s', $response->getContent(), $matches);
        self::assertNotEmpty($matches[1] ?? null);
        $javascript = <<<'JS'
const assert = require('node:assert/strict');
const vm = require('node:vm');
const scenario = process.argv[1];
const source = require('node:fs').readFileSync(0, 'utf8');
const events = {};
let initialize;
let submitted = 0;
let reloaded = 0;
let verified = ['verified', 'complete'].includes(scenario);
const payload = {value: verified ? 'proof' : ''};
let storedPayload;
const element = {setAttribute() {}, removeAttribute() {}, hidden: true, textContent: ''};
const retry = {...element, addEventListener: (_, callback) => {events.retry = callback;}};
const form = {
    elements: {namedItem: () => payload},
    setAttribute() {}, closest: () => element, classList: {add() {}},
    querySelector(selector) {
        if (selector === 'input[data-altcha-payload]') return storedPayload;
        if (selector.startsWith('input[name=')) return payload;
        if (selector === '.verification-retry') return retry;
        return element;
    },
    appendChild(input) {storedPayload = input;},
    submit() {submitted++; assert.equal(storedPayload.value, 'proof');}
};
const widget = {
    getState: scenario === 'late' ? undefined : () => verified ? 'verified' : 'verifying',
    getAttribute: () => 'invisible', setAttribute() {}, closest: () => form,
    addEventListener: (name, callback) => {events[name] = callback;},
    reset() {verified = false;},
    verify() {
        verified = true;
        payload.value = 'proof';
        events.statechange({detail: {state: 'verified', payload: 'proof'}});
        return Promise.resolve();
    }
};
vm.runInNewContext(source, {
    document: {
        readyState: scenario === 'complete' ? 'complete' : 'loading',
        querySelector: () => widget, createElement: () => ({setAttribute() {}})
    },
    window: {addEventListener: (_, callback) => {initialize = callback;}, location: {reload: () => {reloaded++;}}},
    setTimeout(callback, delay) {if (delay === 120) callback(); return 1;},
    clearTimeout() {}
});
if (scenario !== 'complete') initialize();
if (scenario === 'late') {
    verified = true;
    payload.value = 'proof';
    widget.getState = () => 'verified';
    events.load();
} else if (scenario === 'events') {
    events.statechange({detail: {state: 'verified', payload: 'proof'}});
    events.verified({detail: {payload: 'proof'}});
} else if (scenario === 'retry') {
    events.statechange({detail: {state: 'error'}});
    events.retry();
}
assert.equal(reloaded, 0, 'verification must recover without reloading');
assert.equal(submitted, 1, 'completed verification must submit exactly once');
console.log('ok');
JS;
        $process = new Process(['node', '-e', $javascript, $scenario]);
        $process->setInput($matches[1]);
        $process->mustRun();

        self::assertSame('ok', trim($process->getOutput()));
    }
}

<?php

namespace BillingServ\LaravelWaf\Tests;

use BillingServ\LaravelWaf\WafServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [WafServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('laravel-waf.enabled', true);
        $app['config']->set('laravel-waf.ddos.enabled', true);
        $app['config']->set('laravel-waf.ddos.global', [
            'max_attempts' => 100,
            'decay_seconds' => 60,
        ]);
        $app['config']->set('laravel-waf.ddos.routes', [
            '*' => [
                'max_attempts' => 2,
                'decay_seconds' => 60,
            ],
        ]);
        $app['config']->set('laravel-waf.challenge.enabled', true);
        $app['config']->set('laravel-waf.agent.enabled', false);
        $app['config']->set('laravel-waf.metrics.enabled', false);
        $app['config']->set('laravel-waf.challenge.cookie_secret', 'test-challenge-secret');
        $app['config']->set('laravel-waf.challenge.cookie_secure', false);
    }
}

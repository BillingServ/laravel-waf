<?php

use BillingServ\LaravelWaf\Http\Controllers\MetricsController;
use Illuminate\Support\Facades\Route;

Route::middleware(config('laravel-waf.metrics.middleware', []))
    ->get(config('laravel-waf.metrics.route', '_waf/metrics'), MetricsController::class)
    ->name('laravel-waf.metrics');

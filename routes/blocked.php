<?php

use BillingServ\LaravelWaf\Http\Controllers\ChallengeController;
use Illuminate\Support\Facades\Route;

$path = trim(ltrim((string) config('laravel-waf.challenge.blocked_path', '_waf/blocked'), '/')) ?: '_waf/blocked';
$name = (string) config('laravel-waf.challenge.blocked_route', 'laravel-waf.blocked') ?: 'laravel-waf.blocked';

Route::get($path, [ChallengeController::class, 'blocked'])->name($name);

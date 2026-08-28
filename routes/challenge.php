<?php

use BillingServ\LaravelWaf\Http\Controllers\ChallengeController;
use Illuminate\Support\Facades\Route;

$path = trim(ltrim((string) config('laravel-waf.challenge.path', '_waf/challenge/verify'), '/')) ?: '_waf/challenge/verify';
$name = (string) config('laravel-waf.challenge.verify_route', 'laravel-waf.challenge.verify') ?: 'laravel-waf.challenge.verify';

Route::post($path, [ChallengeController::class, 'verify'])->name($name);
Route::get('_waf/challenge', [ChallengeController::class, 'show'])->name('laravel-waf.challenge.page');

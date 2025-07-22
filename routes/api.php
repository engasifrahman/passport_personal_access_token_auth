<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\v1\Auth\LoginController;
use App\Http\Controllers\API\v1\Auth\LogoutController;
use App\Http\Controllers\API\v1\Auth\RegisterController;
use App\Http\Controllers\API\v1\Auth\ResetPasswordController;
use App\Http\Controllers\API\v1\Auth\ForgotPasswordController;
use App\Http\Controllers\API\v1\OAuth\AuthCodeGrantController;
use App\Http\Controllers\API\v1\Auth\EmailVerificationController;

Route::prefix('/v1')->group(function () {
    Route::get('/health', fn () => 'Health is good!');

    Route::post('/register', RegisterController::class);
    Route::post('/login', LoginController::class)->name('login');
    Route::post('/resend-verification-mail', [EmailVerificationController::class, 'resend']);
    Route::post('/forgot-password', ForgotPasswordController::class);
    Route::post('/reset-password', ResetPasswordController::class)->name('password.reset');

    Route::middleware('signed')->group(function () {
        Route::post('/verify-email/{id}/{hash}', [EmailVerificationController::class, 'verify'])->name('verification.verify');
    });

    Route::middleware(['auth:api', 'verified'])->group(function () {
        Route::middleware(['role:Admin | Super Admin'])->group(function () {
            Route::get('/admin', function (Request $request) {
                return $request->user();
            });
        });

        Route::middleware(['role:User'])->group(function () {
            Route::get('/user', function (Request $request) {
                return $request->user();
            });
        });

        Route::middleware(['role:Subscriber'])->group(function () {
            Route::get('/subscriber', function (Request $request) {
                return $request->user();
            });
        });

        Route::post('/logout', LogoutController::class);
    });
});


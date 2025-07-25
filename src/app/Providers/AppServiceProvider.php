<?php

namespace App\Providers;

use App\Models\User;
use Illuminate\Support\Carbon;
use Laravel\Passport\Passport;
use App\Mixins\ApiResponseMacros;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Response;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Auth\Notifications\ResetPassword;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Ignore Passport's default routes as this app only for personal access token authentication
        Passport::ignoreRoutes();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Register a global Gate policy to allow all abilities for administrators
        // This allows administrators to bypass all authorization checks
        Gate::before(function (User $user, string $ability) {
            if ($user->isAdministrator()) {
                return true;
            }
        });

        // Load Response macros for seamless API responses
        Response::mixin(new ApiResponseMacros());

        // Set the default channel for the current Log facade instance
        if (app()->runningInConsole()) {
            // This affects all subsequent calls to Log::info(), Log::error(), etc.
            // without explicitly calling Log::channel()
            Log::setDefaultDriver('cli');
        }

        // Listen for all database queries to log and debug them.
        DB::listen(function (QueryExecuted $query) {
            // Prepare bindings for insertion into SQL
            $bindings = $query->bindings;
            foreach ($bindings as $key => $value) {
                if (is_string($value)) {
                    $bindings[$key] = "'{$value}'"; // Quote strings
                } elseif (is_null($value)) {
                    $bindings[$key] = 'NULL';
                }
            }

            // Replace '?' with actual bindings
            $fullSql = vsprintf(str_replace('?', '%s', $query->sql), $bindings);

            $logChannel = app()->runningInConsole() ? 'cli_sql' : 'sql';

            Log::channel($logChannel)->info("Full SQL Query:", [
                'sql' => $fullSql,
                'time' => $query->time . 'ms',
                'connection' => $query->connectionName
            ]);
        });

        // Customizes the email verification link to point to your frontend URL.
        VerifyEmail::createUrlUsing(function (MustVerifyEmail $notifiable) {
            $id = $notifiable->getKey();
            $hash = sha1($notifiable->getEmailForVerification());

            // Generate the signed URL for the *backend* verification route
            $temporarySignedRoute = URL::temporarySignedRoute(
                'verification.verify', // This is the name of your API verification route
                Carbon::now()->addMinutes(config('auth.verification.expire', 60)),
                [
                    'id' => $id,
                    'hash' => $hash,
                ]
            );

            // Convert the backend route into a frontend route
            // Example: https://api.example.com/api/v1/verify-email/... => https://frontend.com/verify-email/...
            // Parse query parameters
            $parsedUrl = parse_url($temporarySignedRoute);
            parse_str($parsedUrl['query'] ?? '', $queryParams);

            // Add 'id' and 'hash' to query (they are part of the original path in Laravel)
            $queryParams['id'] = $id;
            $queryParams['hash'] = $hash;

            // Build new query string
            $queryString = http_build_query($queryParams);

            // Frontend URL (ensure no trailing slash)
            $frontendBaseUrl = rtrim(config('app.frontend_url') ?: env('FRONTEND_URL', 'http://localhost:3000'), '/');
            $frontendMailVerifyPath = rtrim(config('app.frontend_mail_verify_path') ?: env('FRONTEND_MAIL_VERIFY_PATH', 'verify-email'), '/');

            // Final URL with frontend-friendly query parameters
            return "{$frontendBaseUrl}/{$frontendMailVerifyPath}?{$queryString}";
        });

        // Customizes the password reset link to point to your frontend URL with query params
        ResetPassword::createUrlUsing(function (CanResetPassword $notifiable, string $token) {
            // Generate the backend's signed URL.
            $queryString = http_build_query([
                'token' => $token,
                'email' => $notifiable->getEmailForPasswordReset(),
            ]);

            // Frontend URL (ensure no trailing slash)
            $frontendBaseUrl = rtrim(config('app.frontend_url') ?: env('FRONTEND_URL', 'http://localhost:3000'), '/');
            $frontendResetPasswordPath = rtrim(config('app.frontend_reset_password_path') ?: env('FRONTEND_RESET_PASSWORD_PATH', 'reset-password'), '/');

            // Construct the final frontend password reset URL.
            return "{$frontendBaseUrl}'/{$frontendResetPasswordPath}?{$queryString}";
        });
    }
}

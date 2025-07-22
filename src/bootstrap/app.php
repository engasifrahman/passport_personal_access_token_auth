<?php

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Illuminate\Foundation\Application;
use App\Http\Middleware\RoleMiddleware;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Validation\ValidationException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'role' => RoleMiddleware::class
        ]);
    })

    ->withExceptions(function (Exceptions $exceptions) {
        $isProd = app()->environment('production');
        $isDebugging = !$isProd && config('app.debug');

        // Handle ValidationException
        $exceptions->render(function (ValidationException $e, Request $request) {
            if ($request->expectsJson()) {
                $message = 'Validation failed!';
                $errors = $e->errors();

                return response()->error($message, Response::HTTP_UNPROCESSABLE_ENTITY, $errors);
            }

            return null; // Let Laravel's default web handler take over
        });

        // Handle specific HTTP-related Exceptions
        $exceptions->render(function (AuthenticationException $e, Request $request) {
            if ($request->expectsJson()) {
                return response()->error('Unauthenticated.', Response::HTTP_UNAUTHORIZED);
            }

            return null;
        });

        $exceptions->render(function (AuthorizationException $e, Request $request) {
            if ($request->expectsJson()) {
                $message = $e->getMessage() ?: 'This action is unauthorized.';

                return response()->error($message, Response::HTTP_FORBIDDEN);
            }

            return null;
        });

        $exceptions->render(function (NotFoundHttpException $e, Request $request) use($isDebugging) {
            if ($request->expectsJson()) {
                $message = 'Resource not found.';
                $statusCode = $e->getStatusCode() ?? Response::HTTP_NOT_FOUND;
                if ($isDebugging) {
                    $message = $e->getMessage() ?: Response::$statusTexts[$statusCode] ?? $message;
                }

                return response()->error($message, $statusCode);
            }

            return null;
        });

        $exceptions->render(function (MethodNotAllowedHttpException $e, Request $request) use($isDebugging) {
            if ($request->expectsJson()) {
                $allowedMethods = $e->getHeaders()['Allow'] ?? '';
                $message = 'Method not allowed.';

                $debugInfo = null;
                if ($isDebugging) {
                    $debugInfo = ['allowed_methods' => explode(', ', $allowedMethods)];
                }

                return response()->error($message, Response::HTTP_METHOD_NOT_ALLOWED, $debugInfo);
            }

            return null;
        });

        $exceptions->render(function (HttpException $e, Request $request) {
            if ($request->expectsJson()) {
                $statusCode = $e->getStatusCode();
                $message = $e->getMessage() ?: Response::$statusTexts[$statusCode] ?? 'An HTTP error occurred.';

                return response()->error($message, $statusCode);
            }

            return null;
        });

        // Handle QueryException
        $exceptions->render(function (QueryException $e, Request $request) use($isDebugging){
            if ($request->expectsJson()) {
                // Database errors are typically 500 Internal Server Error
                $statusCode = Response::HTTP_INTERNAL_SERVER_ERROR;

                Log::error($e);

                $message = $isDebugging
                    ? 'A database query failed: ' . $e->getMessage()
                    : 'A database error occurred. Please try again later.';

                $debugInfo = null;
                if ($isDebugging) {
                    $debugInfo = [
                        'exception' => get_class($e),
                        'message'   => $e->getMessage(),
                        'file'      => $e->getFile(),
                        'line'      => $e->getLine(),
                        'sql'       => $e->getSql(),
                        'bindings'  => $e->getBindings(),
                        'code'      => $e->getCode(),
                        'trace'     => collect($e->getTrace())->take(15)->toArray(),
                    ];
                }

                return response()->error($message, $statusCode, $debugInfo);
            }

            return null;
        });

        // Catch-all for all other Throwables
        $exceptions->render(function (Throwable $th, Request $request) use($isDebugging){
            if ($request->expectsJson()) {
                // Default status code fallback
                $statusCode = $th->getCode();
                $statusCode = is_int($statusCode) && $statusCode >= Response::HTTP_CONTINUE && $statusCode <= Response::HTTP_NETWORK_AUTHENTICATION_REQUIRED
                 ? $statusCode
                 : Response::HTTP_INTERNAL_SERVER_ERROR;

                Log::error($th);

                $message = $isDebugging
                    ? ($th->getMessage() ?: 'An unexpected error occurred.')
                    : 'Something went wrong. Please try again later.';

                $debugInfo = null;
                if ($isDebugging) {
                    $debugInfo = [
                    'exception' => get_class($th),
                    'message'   => $th->getMessage(),
                    'file'      => $th->getFile(),
                    'line'      => $th->getLine(),
                    'trace'     => collect($th->getTrace())->take(15)->toArray(),
                    ];
                }

                return response()->error($message, $statusCode, $debugInfo);
            }

            return null;
        });
    })->create();

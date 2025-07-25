<?php
namespace App\Http\Controllers\API\v1\Auth;

use Throwable;
use Laravel\Passport\Token;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;

class LogoutController extends Controller
{
/**
     * Log out the authenticated user by revoking their current access token.
     *
     * @param  Request  $request
     * @return JsonResponse
     */
    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();

        try {
            $token = $user->currentAccessToken();

            if ($token) {
                // Revoke the access token and its associated refresh token
                $token->revoke();
            }

            Log::info('User logged out successfully.', [
                'user_id' => $user->id,
                'email' => $user->email ?? 'N/A',
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            return response()->success('Logged out successfully.');

        } catch (Throwable $e) {
            Log::error('Failed to revoke access/refresh token during logout.', [
                'user_id' => $user->id ?? 'N/A',
                'email' => $user->email ?? 'N/A',
                'exception_message' => $e->getMessage(),
                'exception_file' => $e->getFile(),
                'exception_line' => $e->getLine(),
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            return response()->error('Failed to log out. An internal server error occurred.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Log out the authenticated user from all devices by revoking all their access and associated refresh tokens.
     *
     * @param  Request  $request
     * @return JsonResponse
     */
    public function logoutAll(Request $request): JsonResponse
    {
        $user = $request->user();

        try {
            // Revoke all tokens and associated refresh tokens
            $user->tokens->each(function (Token $token) use ($user) {
                try {
                    $token->revoke();
                    $token->refreshToken?->revoke();

                    Log::info('Token revoked for user.', [
                        'user_id' => $user->id,
                        'token_id' => $token->id,
                    ]);
                } catch (Throwable $e) {
                    Log::warning('Failed to revoke individual token during logout-all.', [
                        'user_id' => $user->id,
                        'token_id' => $token->id,
                        'error'    => $e->getMessage(),
                    ]);

                    throw $e;
                }
            });

            // Final confirmation log
            Log::info('User logged out from all devices.', [
                'user_id' => $user->id,
                'email' => $user->email ?? 'N/A',
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            return response()->success('Logged out from all devices.');
        } catch (Throwable $e) {
            Log::error('Logout from all devices failed.', [
                'user_id' => $user->id ?? 'N/A',
                'email' => $user->email ?? 'N/A',
                'exception_message' => $e->getMessage(),
                'exception_file' => $e->getFile(),
                'exception_line' => $e->getLine(),
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            return response()->error('Failed to log out from all devices.', 500);
        }
    }
}


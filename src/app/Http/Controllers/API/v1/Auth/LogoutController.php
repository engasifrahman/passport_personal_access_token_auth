<?php
namespace App\Http\Controllers\API\v1\Auth;

use Throwable;
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
    public function __invoke(Request $request): JsonResponse
    {
        // Retrieve the authenticated user from the request.
        $user = $request->user();

        try {
            // Delete the current access token associated with the authenticated user.
            $user->currentAccessToken()->delete();

            // Log the successful logout for auditing purposes
            Log::info('User logged out successfully.', [
                'user_id' => $user->id,
                'email' => $user->email ?? 'N/A',
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            // Return a success JSON response
            return response()->success('Logged out successfully.'); // Using Response::HTTP_OK

        } catch (Throwable $e) {
            // Log any unexpected errors that occur during the token deletion process.
            Log::error('Failed to revoke current access token during logout.', [
                'user_id' => $user->id ?? 'N/A',
                'email' => $user->email ?? 'N/A',
                'exception_message' => $e->getMessage(),
                'exception_file' => $e->getFile(),
                'exception_line' => $e->getLine(),
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            // Return an error JSON response with a 500 status code
            return response()->error('Failed to log out. An internal server error occurred.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}


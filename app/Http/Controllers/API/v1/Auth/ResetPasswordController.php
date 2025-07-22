<?php
namespace App\Http\Controllers\API\v1\Auth;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;

class ResetPasswordController extends Controller
{
    /**
     * Reset the given user's password.
     *
     * @param  Request  $request
     * @return JsonResponse
     */
    public function __invoke(Request $request): JsonResponse {
        $email = $request->input('email');

        // Log the password reset attempt
        Log::info('Password reset attempt initiated.', [
            'email' => $email,
            'ip_address' => $request->ip(),
            'user_agent' => $request->header('User-Agent'),
        ]);

        // Perform the password reset
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                // Use forceFill to update the 'password' attribute even if it's not in $fillable
                $user->forceFill([
                    'password' => Hash::make($password),
                ])->save();
            }
        );

        // Handle the response based on the status returned by Password::reset()
        switch ($status) {
            case Password::PASSWORD_RESET:
                Log::info('Password successfully reset.', ['email' => $email]);
                return response()->success('Your password has been reset successfully.');

            case Password::INVALID_TOKEN:
                Log::warning('Password reset failed due to invalid or expired token.', [
                    'email' => $email,
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->header('User-Agent'),
                ]);
                // Return 403 Forbidden for security, indicating that the token does not grant access.
                return response()->error('The password reset token is invalid or has expired.', Response::HTTP_FORBIDDEN);

            case Password::INVALID_USER:
                Log::warning('Password reset failed: User not found for email or token mismatch.', [
                    'email' => $email,
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->header('User-Agent'),
                ]);
                // For security, present the same error message as INVALID_TOKEN to prevent user enumeration.
                return response()->error('The password reset token is invalid or has expired.', Response::HTTP_FORBIDDEN);

            case Password::RESET_THROTTLED:
                Log::warning('Password reset attempt throttled.', [
                    'email' => $email,
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->header('User-Agent'),
                ]);
                // Inform the user about throttling with a 429 status code.
                return response()->error('Too many password reset attempts. Please try again later.', Response::HTTP_TOO_MANY_REQUESTS);

            default:
                // Catch any other unexpected status codes from Password::reset()
                Log::error('An unexpected password reset status occurred.', ['email' => $email, 'status' => $status]);
                // Return a generic internal server error for unhandled cases.
                return response()->error('Could not reset password. Please try again.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

<?php
namespace App\Http\Controllers\API\v1\Auth;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Password;

class ForgotPasswordController extends Controller
{
    /**
     * Send a password reset link to the given user.
     *
     * @param  Request  $request
     * @return JsonResponse
     */
    public function __invoke(Request $request): JsonResponse
    {
        // Validate the incoming request data
        $request->validate([
            'email' => 'required|email',
        ]);

        $email = $request->input('email');

        // Log the password reset attempt
        Log::info('Password reset link requested', [
            'email' => $email,
            'ip_address' => $request->ip(),
            'user_agent' => $request->header('User-Agent'),
        ]);

        // Send the password reset link
        // Laravel's Password::sendResetLink() is designed to prevent user enumeration.
        // It returns Password::RESET_LINK_SENT even if the user does not exist,
        // but it only sends an email if the user is found.
        $status = Password::sendResetLink($request->only('email'));

        switch ($status) {
            case Password::RESET_LINK_SENT:
                Log::info('Password reset link sent (or simulated) successfully.', ['email' => $email]);

                return response()->success('If your email address exists in our database, a password reset link has been sent to it.');

            case Password::RESET_THROTTLED:
                Log::warning('Password reset request throttled.', ['email' => $email, 'ip_address' => $request->ip()]);

                return response()->error('Too many password reset attempts. Please try again later.', Response::HTTP_TOO_MANY_REQUESTS);

            default:
                Log::error('An unexpected password reset status occurred.', ['email' => $email, 'status' => $status]);
                return response()->error('Could not send password reset link. Please try again.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

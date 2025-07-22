<?php
namespace App\Http\Controllers\API\v1\Auth;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\EmailVerificationRequest;

class EmailVerificationController extends Controller
{
    /**
     * Mark the user's email address as verified.
     *
     * @param  EmailVerificationRequest  $request
     * @return JsonResponse
     */
    public function verify(Request $request, $id, $hash): JsonResponse
    {
        $user = User::findOrFail($id);

        // Log the verification attempt
        Log::info('Attempting to verify email for user ID: ' . $user->id . ' email: ' . $user->email, [
            'request_ip' => $request->ip(),
            'user_agent' => $request->header('User-Agent'),
        ]);

        // Check if the email is already verified
        if ($user->hasVerifiedEmail()) {
            Log::info('Email already verified for user ID: ' . $user->id . ' email: ' . $user->email);
            return response()->error('Email already verified!', Response::HTTP_CONFLICT);
        }

        // Match the mail hash with the expected hash
        $expectedHash = sha1($user->email);
        if (!hash_equals($expectedHash, $hash)) {
             Log::warning('Potentially tampered email hash provided for user ID: ' . $user->id . ' email: ' . $user->email, [
                'provided_hash' => $hash,
                'expected_hash' => $expectedHash,
                'request_ip' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);
            return response()->error('Invalid verification link!', Response::HTTP_FORBIDDEN);
        }

        try {
            // Mark the email as verified. This updates the 'email_verified_at' timestamp.
            if ($user->markEmailAsVerified()) {
                // Dispatch the Verified event, which can trigger other listeners (e.g., welcome emails)
                event(new Verified($user));
                Log::info('Email successfully verified for user ID: ' . $user->id . ' email: ' . $user->email);
                return response()->success('Email verified successfully!');
            } else {
                // This case is less common for markEmailAsVerified but could indicate a database issue
                Log::error('Failed to mark email as verified (method returned false) for user ID: ' . $user->id . ' email: ' . $user->email);
                return response()->error(
                    'Failed to verify email. Please try again.',
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }
        } catch (Throwable $th) {
            Log::error("An unexpected error occurred during email verification for user ID: " . $user->id . " email: " . $user->email . " - " . $th->getMessage(), [
                'exception' => $th,
                'request_ip' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);
            return response()->error(
                'An unexpected server error occurred during email verification. Please try again later.',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Resend the email verification notification.
     *
     * @param  Request  $request
     * @return JsonResponse
     */
    public function resend(Request $request): JsonResponse
    {
        // Validate the request data first
        $request->validate([
            'email' => 'required|email',
        ]);

        // Log the start of the resend attempt
        Log::info('Attempting to resend email verification for email: ' . $request->email);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            Log::info('Resend email verification: User not found for email: ' . $request->email);

            return response()->error('User not found!', Response::HTTP_NOT_FOUND);
        }

        if ($user->hasVerifiedEmail()) {
            Log::info('Resend email verification: Email already verified for user ID: ' . $user->id . ' email: ' . $user->email);
            return response()->error('Email already verified!', Response::HTTP_CONFLICT);
        }

        try {
            $user->sendEmailVerificationNotification();
            Log::info('Email verification notification resent for user ID: ' . $user->id . ' email: ' . $user->email);

            return response()->success('Verification link sent!');

        } catch (Throwable $th) {
            // Log the full exception details
            Log::error("Failed to resend email verification for user ID: " . $user->id . " email: " . $user->email . " - " . $th->getMessage(), [
                'exception' => $th,
                'request_ip' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            // Return a generic server error for unexpected issues during email sending
            return response()->error(
                'Failed to send verification link. Please try again later.',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }
}

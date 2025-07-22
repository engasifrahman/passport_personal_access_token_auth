<?php
namespace App\Http\Controllers\API\v1\Auth;

use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\API\v1\Auth\LoginRequest;

class LoginController extends Controller
{
/**
     * Handle the incoming login request.
     *
     * @param  \App\Http\Requests\LoginRequest  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function __invoke(LoginRequest $request): JsonResponse
    {
        // Log the start of the login attempt
        Log::info('Login attempt for email: ' . $request->email, ['ip_address' => $request->ip()]);

        $user = User::where('email', $request->email)->first();
        // Check for user existence and password validity
        if (!$user || !Hash::check($request->password, $user->password)) {
            // Log failed login attempt due to invalid credentials
            Log::warning('Login failed: Invalid credentials for email: ' . $request->email, ['ip_address' => $request->ip()]);
            return response()->error('Invalid credentials', Response::HTTP_UNAUTHORIZED);
        }

        // Check if the user's email is verified
        if (!$user->hasVerifiedEmail()) {
            // Log failed login attempt due to unverified email
            Log::warning('Login failed: Email not verified for user ID: ' . $user->id . ' email: ' . $user->email, ['ip_address' => $request->ip()]);
            return response()->error('Please verify your email first.', Response::HTTP_FORBIDDEN);
        }

        try {
            // Create a new Personal Passport token for the user
            $token = $user->createPersonalToken($user->email);
            if (!$token) {
                // Log failed login attempt due to token creation failure
                Log::error('Login failed: Unable to create token for user ID: ' . $user->id . ' email: ' . $user->email, ['ip_address' => $request->ip()]);
                return response()->error('Unable to create token. Please try again later.', Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Log successful token creation
            Log::info('Sanctum token created for user ID: ' . $user->id . ' email: ' . $user->email);

            $data = [
                'token' => $token,
                'user' => $user->only(['id', 'name', 'email', 'role_names']), // Return selected user fields for security/efficiency
            ];

            // Log successful login
            Log::info('User login successful for user ID: ' . $user->id . ' email: ' . $user->email, ['ip_address' => $request->ip()]);

            return response()->success('Login Successful!', Response::HTTP_OK, $data);

        } catch (Throwable $th) {
            Log::error("Login failed unexpectedly during token creation for user ID: " . $user->id . " email: " . $user->email . " - " . $th->getMessage(), [
                'exception' => $th,
                'ip_address' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            return response()->error('An unexpected error occurred during login. Please try again later.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

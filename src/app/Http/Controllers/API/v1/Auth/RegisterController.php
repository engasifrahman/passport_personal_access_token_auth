<?php
namespace App\Http\Controllers\API\v1\Auth;

use Throwable;
use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Registered;
use App\Http\Requests\API\v1\Auth\RegistrationRequest;

class RegisterController extends Controller
{
    /**
     * Handle the user registration request.
     *
     * @param  RegistrationRequest $request
     * @return JsonResponse
     */
    public function __invoke(RegistrationRequest $request): JsonResponse
    {
        // Log the start of the registration attempt
        Log::info('Attempting user registration for email: ' . $request->email);

        DB::beginTransaction();

        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => $request->password,
            ]);

            // Log successful user creation
            Log::info('User created successfully for user ID: ' . $user->id . ' email: ' . $user->email);

            // Ensure the user object exists before sending the verification notification
            if ($user) {
                event(new Registered($user));

                // Log the email verification notification attempt
                Log::info('Email verification notification sent to user: ' . $user->email);
            }

            DB::commit();

            // Log successful transaction commit
            Log::info('User registration transaction committed for email: ' . $request->email);

            return response()->success('User registered successfully. Please verify your email.');

        } catch (Throwable $th) {
            DB::rollBack();

            // Log the full exception details at an error level
            Log::error("User registration failed for email: " . $request->email . " - " . $th->getMessage(), [
                'exception' => $th,
                'request_ip' => $request->ip(),
                'user_agent' => $request->header('User-Agent'),
            ]);

            return response()->error(
                'Registration failed. Please try again later.',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }
}

<?php

namespace App\Mixins;

use Closure;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\JsonResource;

class ApiResponseMacros
{
    /**
     * Respond with a success JSON response.
     *
     * @return Closure
     */
    public function success(): Closure
    {
        return function (string $message = 'Operation successful!', int $statusCode = Response::HTTP_OK, mixed $data = null): JsonResponse {
            $response = [
                'status' => true,
                'message' => $message,
            ];
            $meta = null;
            $links = null;

            // Handle Laravel API Resources
            if ($data instanceof JsonResource) {
                // Convert the resource to an array, respecting its toArray() method
                $resourceData = $data->toArray(request());

                if (JsonResource::$wrap && array_key_exists(JsonResource::$wrap, $resourceData) && (array_key_exists('meta', $resourceData) || array_key_exists('links', $resourceData))) {
                    $data = $resourceData[JsonResource::$wrap];
                    $meta = $resourceData['meta'] ?? null;
                    $links = $resourceData['links'] ?? null;
                } else {
                    $data = JsonResource::$wrap && array_key_exists(JsonResource::$wrap, $resourceData) ? $resourceData[JsonResource::$wrap] : $resourceData;
                }
            }

            if (!is_null($data)) {
                $response['data'] = $data;
            }

            if (!is_null($meta)) {
                $response['meta'] = $meta;
            }

            if (!is_null($links)) {
                $response['links'] = $links;
            }

            return response()->json($response, $statusCode);
        };
    }

    /**
     * Respond with an error JSON response.
     *
     * @return Closure
     */
    public function error(): Closure
    {
        return function (string $message = 'Bad request!', int $statusCode = Request::BAD_REQUEST, mixed $errors = null): JsonResponse {
            $response = [
                'status' => false,
                'message' => $message,
            ];

            if (!is_null($errors)) {
                $response['errors'] = $errors;
            }

            return response()->json($response, $statusCode);
        };
    }
}

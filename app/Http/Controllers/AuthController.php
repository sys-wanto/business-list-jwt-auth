<?php

namespace App\Http\Controllers;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use Response;
use Validator;


class AuthController extends Controller
{
    public function __construct(Request $request)
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'is_error' => true,
                'message' => $validator->errors()], 422);
        }

        $credentials = $request->only('email', 'password');

        $token = Auth::attempt($credentials);
        if (!$token) {
            return response()->json([
                'is_error' => true,
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = Auth::authenticate();
        return response()->json([
            'is_error' => false,
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);

    }

    public function register(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'is_error' => true,
                'message' => $validator->errors()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        $token = Auth::login($user);

        return response()->json([
            'is_error' => false,
            'message' => 'User created successfully',
            'user' => $user,
            'Auth' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);

    }

    public function logout(Request $request)
    {
        Auth::logout();
        return response()->json([
            'is_error' => false,
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh(Request $request)
    {
        return response()->json([
            'is_error' => false,
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
        // $this->validate($request, [
        //     'token' => 'required'
        // ]);
        // try {
        //     Auth::invalidate($request->bearerToken());
        //     return response()->json([
        //         'is_error' => false,
        //         'user' => Auth::user(),
        //         'authorisation' => [
        //             'token' => Auth::refresh(),
        //             'type' => 'bearer',
        //         ]
        //     ]);
        // } catch (AuthorizationException $exception) {
        //     return response()->json([
        //         'is_error' => true,
        //         'message' => 'Token Blacklisted',
        //     ], Response::HTTP_INTERNAL_SERVER_ERROR);

        // }
        // $auth = Auth::check();
        // if (!$auth) {

        // }

    }
}
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Rublon\Rublon as Rublon;
use Rublon\RublonCallback;
use App\Models\User;
class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     *
     * @return \Illuminate\View\View
     */
    public function create()
    {
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     *
     * @param  \App\Http\Requests\Auth\LoginRequest  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function store(LoginRequest $request)
    {
        $request->authenticate();

        $rublon = new Rublon(
            env('RUBLON_TOKEN'),
            env('RUBLON_KEY'),
            env('RUBLON_URL'),
        );

        try { // Initiate a Rublon authentication transaction
            $url = $rublon->auth(
                $callbackUrl = "http://localhost:8040/rublon-callback",
                Auth::user()->id, // App User ID
                Auth::user()->email// User email
            );

            if (!empty($url)) {
                Auth::logout();
                return redirect()->away($url);
            } else {
                // User is not protected by Rublon, so bypass the second factor.
                $request->session()->regenerate();
                return redirect()->to('dashboard');
            }
        } catch (UserBypassedException $e) {
            return redirect()->to('login');
        } catch (RublonException $e) {
            // An error occurred
            die($e->getMessage());
        }

        return redirect()->intended(RouteServiceProvider::HOME);
    }

    public function rublonCallback(Request $request) {

        $rublon = new Rublon(
            env('RUBLON_TOKEN'),
            env('RUBLON_KEY'),
            env('RUBLON_URL'),
        );

        try {
            $callback = new RublonCallback($rublon);
            $request->session()->regenerate();
            $callback->call(
                $successHandler = function($appUserId,  RublonCallback $callback) {
                    Auth::loginUsingId($appUserId);
                    if (Auth::check()) {
                        return redirect()->to('dashboard');
                    } else {
                        return redirect()->to('login');
                    }
                },
                $cancelHandler = function(RublonCallback $callback) {
                    return redirect()->to('login');
                }
            );
            return redirect()->to('dashboard');
        } catch (RublonException $e) {
            die($e->getMessage());
        }
        return redirect()->to('dashboard');
    }

    /**
     * Destroy an authenticated session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function destroy(Request $request)
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }
}

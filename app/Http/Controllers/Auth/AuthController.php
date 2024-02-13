<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Validation\ValidationException;
use Illuminate\Validation\Rules\Password as RulesPassword;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\Rules;
use Illuminate\View\View;
use Illuminate\Support\Str;

class AuthController extends Controller
{

    // frontend views

    public function registerView(): View
    {
        return view('auth.register');
    }

    public function loginView()
    {
        return view('auth.login');
    }

    public function passwordResetView()
    {
        return view('auth.forgot-password');
    }

    public function verifyEmailView(Request $request): View
    {
        return $request->user()->hasVerifiedEmail()
            ? redirect()->intended(RouteServiceProvider::HOME)
            : view('auth.verify-email');
    }
    // reset Password
    public function newPasswordView(Request $request)
    {
        return view('auth.reset-password', ['request' => $request]);
    }

    public function confirmPassView()
    {
        return view('auth.confirm-password');
    }



    public function register(Request $request): RedirectResponse
    {
        $request->validate(
            [
                'name' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:' . User::class],
                'password' => [
                    'required', 'confirmed', 'min:6',
                    'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/'
                ]
            ],
            [
                "password.regex" => "The password must contain at least one uppercase letter, one lowercase letter, and one digit"
            ]
        );

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        event(new Registered($user));

        Auth::login($user);

        return redirect('dashboard');
    }


    public function login(LoginRequest $request)
    {
        $request->authenticate();
        $request->session()->regenerate();
        return redirect()->intended('dashboard');
    }

    public function logout(Request $request)
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect('/');
    }


    public function verifyEmail(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return redirect()->intended('dashboard' . '?verified=1');
        }

        if ($request->user()->markEmailAsVerified()) {
            event(new Verified($request->user()));
        }

        return redirect()->intended('dashboard' . '?verified=1');
    }


    public function passwordReset(Request $request)
    {
        $request->validate([
            'email' => ['required', 'email'],
        ]);

        $status = Password::sendResetLink(
            $request->only('email')
        );

        return $status == Password::RESET_LINK_SENT
            // redirect with success
            ? back()->with('status', __($status))
            //redirect with error
            : back()->withInput($request->only('email'))
            ->withErrors(['email' => __($status)]);
    }



    public function newPassword(Request $request)
    {
        $request->validate([
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed', 'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/'],

        ], [
            "password.regex" => "The password must contain at least one uppercase letter, one lowercase letter, and one digit"
        ]);


        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user) use ($request) {
                $user->forceFill([
                    'password' => Hash::make($request->password),
                    'remember_token' => Str::random(60),
                ])->save();

                event(new PasswordReset($user));
            }
        );

        // redirect the user back 
        return $status == Password::PASSWORD_RESET
            ? redirect()->route('login')->with('status', __($status))
            //redirect with error
            : back()->withInput($request->only('email'))
            ->withErrors(['email' => __($status)]);
    }


    public function emailVerif(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return redirect()->intended('dashboard');
        }

        $request->user()->sendEmailVerificationNotification();

        return back()->with('status', 'verification-link-sent');
    }



    public function confirmPass(Request $request)
    {
        if (!Auth::guard('web')->validate([
            'email' => $request->user()->email,
            'password' => $request->password,
        ])) {
            throw ValidationException::withMessages([
                'password' => __('auth.password'),
            ]);
        }

        $request->session()->put('auth.password_confirmed_at', time());

        return redirect()->intended('dashboard');
    }

    public function updatePassword(Request $request): RedirectResponse
    {
        $validated = $request->validateWithBag('updatePassword', [
            'current_password' => ['required', 'current_password'],
            'password' => ['required', RulesPassword::defaults(), 'confirmed'],
        ]);

        $request->user()->update([
            'password' => Hash::make($validated['password']),
        ]);

        return back()->with('status', 'password-updated');
    }
}

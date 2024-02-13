<?php


use App\Http\Controllers\Auth\AuthController;
use Illuminate\Support\Facades\Route;

// auth routes
Route::middleware('guest')->group(function () {
    Route::get('register', [AuthController::class, 'registerView'])
        ->name('register');
    Route::get('login', [AuthController::class, 'loginView'])
        ->name('login');

    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
});

// Verify Email Routes
Route::middleware('auth')->group(function () {
    Route::get('verify-email', [AuthController::class, 'verifyEmailView'])
        ->name('verification.notice');

    Route::get('verify-email/{id}/{hash}', [AuthController::class, 'verifyEmail'])
        ->middleware(['signed', 'throttle:6,1'])
        ->name('verification.verify');

    Route::post('email/verification-notification', [AuthController::class, 'emailVerif'])
        ->middleware('throttle:6,1')
        ->name('verification.send');
});



// Password Reset Routes
Route::middleware('guest')->group(function () {
    Route::get('forgot-password', [AuthController::class, 'passwordResetView'])
        ->name('password.request');
    Route::post('forgot-password', [AuthController::class, 'passwordReset'])
        ->name('password.email');

    Route::get('reset-password/{token}', [AuthController::class, 'newPasswordView'])
        ->name('password.reset');
    Route::post('reset-password', [AuthController::class, 'newPassword'])
        ->name('password.store');
});
// routes that's protected by auth
Route::middleware('auth')->group(function () {

    Route::get('confirm-password', [AuthController::class, 'confirmPassView'])
        ->name('password.confirm');
    Route::post('confirm-password', [AuthController::class, 'confirmPass']);
    Route::put('password', [AuthController::class, 'updatePassword'])->name('password.update');
    Route::post('logout', [AuthController::class, 'logout'])
        ->name('logout');
});

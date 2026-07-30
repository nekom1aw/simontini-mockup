<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    respond(405, [
        'success' => false,
        'message' => 'Metode permintaan tidak didukung.',
    ]);
}

$requestHost = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
$requestHost = explode(':', $requestHost, 2)[0];
$isLocalRequest = in_array($requestHost, ['localhost', '127.0.0.1', '::1'], true);
$secret = $isLocalRequest
    ? '1x0000000000000000000000000000000AA'
    : trim((string) getenv('TURNSTILE_SECRET_KEY'));
if ($secret === '') {
    respond(503, [
        'success' => false,
        'message' => 'Turnstile belum dikonfigurasi pada server.',
    ]);
}

$token = trim((string) ($_POST['cf-turnstile-response'] ?? ''));
if ($token === '' || strlen($token) > 2048) {
    respond(422, [
        'success' => false,
        'message' => 'Verifikasi keamanan belum lengkap.',
    ]);
}

$expectedAction = trim((string) ($_POST['expected-action'] ?? ''));
$allowedActions = ['subscribe', 'comment', 'reply'];
if (!in_array($expectedAction, $allowedActions, true)) {
    respond(422, [
        'success' => false,
        'message' => 'Jenis verifikasi keamanan tidak valid.',
    ]);
}

$requestData = [
    'secret' => $secret,
    'response' => $token,
    'remoteip' => (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
];
$siteverifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
$responseBody = false;

if (function_exists('curl_init')) {
    $curl = curl_init($siteverifyUrl);
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($requestData),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
    ]);
    $responseBody = curl_exec($curl);
    curl_close($curl);
} else {
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => http_build_query($requestData),
            'timeout' => 10,
        ],
    ]);
    $responseBody = @file_get_contents($siteverifyUrl, false, $context);
}

if ($responseBody === false) {
    respond(503, [
        'success' => false,
        'message' => 'Layanan verifikasi sedang tidak tersedia. Silakan coba lagi.',
    ]);
}

$verification = json_decode($responseBody, true);
if (!is_array($verification) || empty($verification['success'])) {
    $errorCodes = is_array($verification)
        ? implode(', ', (array) ($verification['error-codes'] ?? []))
        : 'invalid-response';
    error_log('Turnstile verification failed: ' . $errorCodes);

    respond(422, [
        'success' => false,
        'message' => 'Verifikasi keamanan gagal atau kedaluwarsa. Silakan coba lagi.',
    ]);
}

if (
    !$isLocalRequest
    && (
    !isset($verification['action'])
    || !is_string($verification['action'])
    || $verification['action'] !== $expectedAction
    )
) {
    respond(422, [
        'success' => false,
        'message' => 'Verifikasi keamanan tidak sesuai.',
    ]);
}

respond(200, ['success' => true]);

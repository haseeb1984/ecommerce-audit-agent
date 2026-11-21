<?php
declare(strict_types=1);

/*
 * Hostinger Shared Hosting storage bridge.
 * Install this directory as public_html/eaa-storage.
 * Only this endpoint is public; every operation requires a timestamped HMAC.
 */

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, private');
header('Pragma: no-cache');

function eaa_fail(int $status, string $message): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

function eaa_header(string $name): string {
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return trim((string)($_SERVER[$key] ?? ''));
}

function eaa_claim_nonce(string $privateRoot, string $nonce, int $timestamp): bool {
    $lockPath = $privateRoot . '/nonce-cache.lock';
    $cachePath = $privateRoot . '/nonce-cache.json';
    $lock = @fopen($lockPath, 'c+');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        if (is_resource($lock)) fclose($lock);
        return false;
    }
    try {
        $entries = [];
        if (is_file($cachePath)) {
            $rawCache = @file_get_contents($cachePath);
            if ($rawCache === false) return false;
            $decoded = json_decode($rawCache, true);
            // Fail closed if replay state is corrupt; never silently reset the nonce cache.
            if (!is_array($decoded)) return false;
            $entries = $decoded;
        }
        $cutoff = time() - 600;
        foreach ($entries as $key => $seenAt) {
            if (!is_int($seenAt) || $seenAt < $cutoff) unset($entries[$key]);
        }
        $nonceHash = hash('sha256', $nonce);
        if (isset($entries[$nonceHash])) return false;
        $entries[$nonceHash] = $timestamp;
        if (count($entries) > 20000) {
            asort($entries, SORT_NUMERIC);
            $entries = array_slice($entries, -10000, null, true);
        }
        $json = json_encode($entries, JSON_UNESCAPED_SLASHES);
        if ($json === false) return false;
        $temp = $cachePath . '.tmp-' . bin2hex(random_bytes(8));
        if (@file_put_contents($temp, $json, LOCK_EX) === false) return false;
        @chmod($temp, 0600);
        if (!@rename($temp, $cachePath)) {
            @unlink($temp);
            return false;
        }
        return true;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function eaa_resolve_key(string $privateRoot, string $key): array {
    if (preg_match('#^reports/([a-f0-9]{64})\.pdf$#D', $key, $m)) {
        return [$privateRoot . '/reports/' . $m[1] . '.pdf', 'application/pdf', 26214400];
    }
    if (preg_match('#^logos/([a-f0-9]{64})\.(png|jpg|webp)$#D', $key, $m)) {
        $mime = ['png' => 'image/png', 'jpg' => 'image/jpeg', 'webp' => 'image/webp'][$m[2]];
        return [$privateRoot . '/logos/' . $m[1] . '.' . $m[2], $mime, 5242880];
    }
    eaa_fail(400, 'Invalid storage key');
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    eaa_fail(405, 'Method not allowed');
}

$configPath = dirname(__DIR__) . '/config.php';
if (!is_file($configPath)) eaa_fail(503, 'Storage bridge is not configured');
$config = require $configPath;
$secret = is_array($config) ? (string)($config['hmac_secret'] ?? '') : '';
if (strlen($secret) < 32 || str_contains($secret, 'REPLACE_WITH_')) {
    eaa_fail(503, 'Storage bridge is not configured');
}

$privateRoot = dirname(__DIR__) . '/private';
foreach ([$privateRoot, $privateRoot . '/reports', $privateRoot . '/logos'] as $dir) {
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        eaa_fail(503, 'Private storage is unavailable');
    }
    @chmod($dir, 0700);
}

$timestampRaw = eaa_header('X-EAA-Timestamp');
$nonce = eaa_header('X-EAA-Nonce');
$operation = eaa_header('X-EAA-Operation');
$storageKey = eaa_header('X-EAA-Storage-Key');
$mime = eaa_header('X-EAA-Mime');
$signature = eaa_header('X-EAA-Signature');
if (!preg_match('/^[0-9]{10}$/D', $timestampRaw)
    || !preg_match('/^[a-f0-9]{48,128}$/D', $nonce)
    || !in_array($operation, ['upload', 'download', 'delete'], true)
    || !preg_match('/^[a-f0-9]{64}$/D', $signature)) {
    eaa_fail(401, 'Invalid authentication headers');
}
$timestamp = (int)$timestampRaw;
$skew = max(30, min(600, (int)($config['clock_skew_seconds'] ?? 300)));
if (abs(time() - $timestamp) > $skew) eaa_fail(401, 'Request timestamp expired');

[$targetPath, $expectedMime, $maxBytes] = eaa_resolve_key($privateRoot, $storageKey);
$contentLength = (string)($_SERVER['CONTENT_LENGTH'] ?? '');
if ($contentLength !== '' && ctype_digit($contentLength)) {
    $declaredLength = (int)$contentLength;
    if ($operation === 'upload' && $declaredLength > $maxBytes) eaa_fail(413, 'File is too large');
    if ($operation !== 'upload' && $declaredLength > 0) eaa_fail(400, 'Request body must be empty');
}
$bodyLimit = $operation === 'upload' ? $maxBytes : 0;
$inputStream = @fopen('php://input', 'rb');
if ($inputStream === false) eaa_fail(400, 'Unable to read request body');
$body = stream_get_contents($inputStream, $bodyLimit + 1);
fclose($inputStream);
if ($body === false) eaa_fail(400, 'Unable to read request body');
if (strlen($body) > $bodyLimit) eaa_fail(413, 'Request body is too large');
$actualMime = $mime !== '' ? $mime : 'application/octet-stream';
$canonical = implode("\n", [
    'POST', $timestampRaw, $nonce, $operation, $storageKey, $actualMime, hash('sha256', $body)
]);
$expectedSignature = hash_hmac('sha256', $canonical, $secret);
if (!hash_equals($expectedSignature, $signature)) eaa_fail(401, 'Request signature invalid');
if (!eaa_claim_nonce($privateRoot, $nonce, $timestamp)) eaa_fail(401, 'Request nonce was already used');

if ($operation === 'upload') {
    if ($actualMime !== $expectedMime) eaa_fail(415, 'File type does not match storage key');
    $limit = $expectedMime === 'application/pdf'
        ? min(26214400, (int)($config['max_report_bytes'] ?? 26214400))
        : min(5242880, (int)($config['max_logo_bytes'] ?? 5242880));
    if ($body === '' || strlen($body) > $limit) eaa_fail(413, 'File is empty or too large');
    $validContent = match ($expectedMime) {
        'application/pdf' => str_starts_with($body, '%PDF-'),
        'image/png' => str_starts_with($body, "\x89PNG\r\n\x1a\n"),
        'image/jpeg' => str_starts_with($body, "\xff\xd8\xff"),
        'image/webp' => substr($body, 0, 4) === 'RIFF' && substr($body, 8, 4) === 'WEBP',
        default => false,
    };
    if (!$validContent) eaa_fail(415, 'File content is invalid');
    if (is_file($targetPath)) eaa_fail(409, 'Storage key already exists');
    $tempPath = dirname($targetPath) . '/.upload-' . bin2hex(random_bytes(16));
    if (@file_put_contents($tempPath, $body, LOCK_EX) === false) eaa_fail(507, 'Unable to store file');
    @chmod($tempPath, 0600);
    if (!@rename($tempPath, $targetPath)) {
        @unlink($tempPath);
        eaa_fail(507, 'Unable to finalize stored file');
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'storage_key' => $storageKey,
        'sha256' => hash('sha256', $body),
        'byte_size' => strlen($body),
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($operation === 'download') {
    if ($body !== '') eaa_fail(400, 'Download request body must be empty');
    if (!is_file($targetPath)) eaa_fail(404, 'Stored file not found');
    $size = filesize($targetPath);
    if ($size === false || $size < 1 || $size > $maxBytes) eaa_fail(500, 'Stored file size is invalid');
    header('Content-Type: ' . $expectedMime);
    header('Content-Length: ' . (string)$size);
    header('Content-Disposition: attachment; filename="download"');
    header('X-Content-Type-Options: nosniff');
    readfile($targetPath);
    exit;
}

if ($body !== '') eaa_fail(400, 'Delete request body must be empty');
if (!is_file($targetPath)) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['deleted' => true], JSON_UNESCAPED_SLASHES);
    exit;
}
if (!@unlink($targetPath)) eaa_fail(500, 'Unable to delete stored file');
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['deleted' => true], JSON_UNESCAPED_SLASHES);

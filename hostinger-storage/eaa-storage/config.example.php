<?php
// Copy this file to config.php on Hostinger and replace the placeholder.
// Keep config.php private: the parent .htaccess explicitly denies HTTP access.
// Use a cryptographically random secret with at least 32 bytes of entropy.
return [
    'hmac_secret' => 'REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_BYTES',
    'max_report_bytes' => 26214400,
    'max_logo_bytes' => 5242880,
    'clock_skew_seconds' => 300,
];

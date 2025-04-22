<?php

declare(strict_types=1);

namespace Ipcrypt\Examples;

require_once __DIR__ . '/../vendor/autoload.php';

use Ipcrypt\IpcryptNd;

/**
 * Example usage of the non-deterministic IPcrypt-ND implementation.
 * 
 * This file demonstrates how to use the IpcryptNd class to encrypt
 * and decrypt both IPv4 and IPv6 addresses using KIASU-BC in a
 * non-deterministic manner with random tweaks.
 */

// Generate a random 16-byte key using the built-in key generator
$key = IpcryptNd::generateKey();

// Example with IPv4 address
$ipv4 = '192.0.2.1';
echo "Original IPv4: $ipv4\n";

// First encryption (will use a random tweak)
$encrypted1 = IpcryptNd::encrypt($ipv4, $key);
echo "First encryption (hex):  " . bin2hex($encrypted1) . "\n";

// Second encryption (will use a different random tweak)
$encrypted2 = IpcryptNd::encrypt($ipv4, $key);
echo "Second encryption (hex): " . bin2hex($encrypted2) . "\n";

// Both decrypt to the same IP
$decrypted1 = IpcryptNd::decrypt($encrypted1, $key);
$decrypted2 = IpcryptNd::decrypt($encrypted2, $key);
echo "First decryption:  $decrypted1\n";
echo "Second decryption: $decrypted2\n";
echo "Same plaintext: " . ($decrypted1 === $decrypted2 ? "Yes" : "No") . "\n\n";

// Example with IPv6 address
$ipv6 = '2001:db8::1';
echo "Original IPv6: $ipv6\n";

// First encryption (will use a random tweak)
$encrypted1 = IpcryptNd::encrypt($ipv6, $key);
echo "First encryption (hex):  " . bin2hex($encrypted1) . "\n";

// Second encryption (will use a different random tweak)
$encrypted2 = IpcryptNd::encrypt($ipv6, $key);
echo "Second encryption (hex): " . bin2hex($encrypted2) . "\n";

// Both decrypt to the same IP
$decrypted1 = IpcryptNd::decrypt($encrypted1, $key);
$decrypted2 = IpcryptNd::decrypt($encrypted2, $key);
echo "First decryption:  $decrypted1\n";
echo "Second decryption: $decrypted2\n";
echo "Same plaintext: " . ($decrypted1 === $decrypted2 ? "Yes" : "No") . "\n\n";

// Demonstrate using a fixed tweak
echo "Using a fixed tweak:\n";
$tweak = random_bytes(8);
$encrypted1 = IpcryptNd::encrypt($ipv4, $key, $tweak);
$encrypted2 = IpcryptNd::encrypt($ipv4, $key, $tweak);
echo "Same ciphertexts with same tweak: " . ($encrypted1 === $encrypted2 ? "Yes" : "No") . "\n"; 
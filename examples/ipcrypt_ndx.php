<?php

declare(strict_types=1);

namespace Ipcrypt\Examples;

require_once __DIR__ . '/../vendor/autoload.php';

use Ipcrypt\IpcryptNdx;

/**
 * Example usage of the non-deterministic IPcrypt-NDX implementation.
 * 
 * This file demonstrates how to use the IpcryptNdx class to encrypt
 * and decrypt both IPv4 and IPv6 addresses using AES-XTS mode.
 * It shows how the same input produces different outputs when
 * encrypted multiple times.
 */

// Generate a random 32-byte key (two AES-128 keys) using the built-in key generator
$key = IpcryptNdx::generateKey();

// Example with IPv4 address
$ipv4 = '192.0.2.1';
echo "Original IPv4: $ipv4\n";

// First encryption (will use a random tweak)
$encrypted1 = IpcryptNdx::encrypt($ipv4, $key);
echo "First encryption (hex):  " . bin2hex($encrypted1) . "\n";

// Second encryption (will use a different random tweak)
$encrypted2 = IpcryptNdx::encrypt($ipv4, $key);
echo "Second encryption (hex): " . bin2hex($encrypted2) . "\n";

// Both decrypt to the same IP
$decrypted1 = IpcryptNdx::decrypt($encrypted1, $key);
$decrypted2 = IpcryptNdx::decrypt($encrypted2, $key);
echo "First decryption:  $decrypted1\n";
echo "Second decryption: $decrypted2\n";
echo "Same plaintext: " . ($decrypted1 === $decrypted2 ? "Yes" : "No") . "\n\n";

// Example with IPv6 address
$ipv6 = '2001:db8::1';
echo "Original IPv6: $ipv6\n";

// First encryption (will use a random tweak)
$encrypted1 = IpcryptNdx::encrypt($ipv6, $key);
echo "First encryption (hex):  " . bin2hex($encrypted1) . "\n";

// Second encryption (will use a different random tweak)
$encrypted2 = IpcryptNdx::encrypt($ipv6, $key);
echo "Second encryption (hex): " . bin2hex($encrypted2) . "\n";

// Both decrypt to the same IP
$decrypted1 = IpcryptNdx::decrypt($encrypted1, $key);
$decrypted2 = IpcryptNdx::decrypt($encrypted2, $key);
echo "First decryption:  $decrypted1\n";
echo "Second decryption: $decrypted2\n";
echo "Same plaintext: " . ($decrypted1 === $decrypted2 ? "Yes" : "No") . "\n\n";

// Demonstrate using a fixed tweak
echo "Using a fixed tweak:\n";
$tweak = random_bytes(16);
$encrypted1 = IpcryptNdx::encrypt($ipv4, $key, $tweak);
$encrypted2 = IpcryptNdx::encrypt($ipv4, $key, $tweak);
echo "Same ciphertexts with same tweak: " . ($encrypted1 === $encrypted2 ? "Yes" : "No") . "\n"; 
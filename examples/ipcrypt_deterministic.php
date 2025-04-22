<?php

declare(strict_types=1);

namespace Ipcrypt\Examples;

require_once __DIR__ . '/../vendor/autoload.php';

use Ipcrypt\IpcryptDeterministic;

/**
 * Example usage of the deterministic IPcrypt implementation.
 * 
 * This file demonstrates how to use the IpcryptDeterministic class
 * to encrypt and decrypt both IPv4 and IPv6 addresses using AES-128
 * in a deterministic manner.
 */

// Generate a random 16-byte key using the built-in key generator
$key = IpcryptDeterministic::generateKey();

// Example with IPv4 address
$ipv4 = '192.0.2.1';
echo "Original IPv4: $ipv4\n";

$encrypted = IpcryptDeterministic::encrypt($ipv4, $key);
echo "Encrypted: $encrypted\n";

$decrypted = IpcryptDeterministic::decrypt($encrypted, $key);
echo "Decrypted: $decrypted\n\n";

// Example with IPv6 address
$ipv6 = '2001:db8::1';
echo "Original IPv6: $ipv6\n";

$encrypted = IpcryptDeterministic::encrypt($ipv6, $key);
echo "Encrypted: $encrypted\n";

$decrypted = IpcryptDeterministic::decrypt($encrypted, $key);
echo "Decrypted: $decrypted\n";

// Demonstrate deterministic behavior
echo "\nDemonstrating deterministic behavior:\n";
$key2 = $key; // Use same key
$encrypted1 = IpcryptDeterministic::encrypt($ipv4, $key);
$encrypted2 = IpcryptDeterministic::encrypt($ipv4, $key2);
echo "Same ciphertexts: " . ($encrypted1 === $encrypted2 ? "Yes" : "No") . "\n"; 
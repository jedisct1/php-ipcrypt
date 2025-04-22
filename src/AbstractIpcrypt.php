<?php

declare(strict_types=1);

namespace Ipcrypt;

use InvalidArgumentException;
use RuntimeException;

/**
 * Abstract base class for IPcrypt implementations.
 *
 * This class provides common functionality for converting between IP addresses
 * and their binary representations, as well as basic cryptographic operations.
 * It also defines the interface for batch processing operations, allowing
 * efficient encryption and decryption of multiple IP addresses.
 *
 * Features:
 * - IP address conversion utilities
 * - Common cryptographic operations
 * - Batch processing interface
 * - IPv4 and IPv6 support
 * - Error handling
 */
abstract class AbstractIpcrypt
{
    /**
     * Convert an IP address to its 16-byte representation.
     *
     * @param string $ip The IP address to convert (IPv4 or IPv6)
     * @return string The 16-byte representation
     * @throws InvalidArgumentException If the IP address is invalid
     */
    public static function ipToBytes(string $ip): string
    {
        $binary = inet_pton($ip);
        if ($binary === false) {
            throw new InvalidArgumentException('Invalid IP address');
        }

        if (strlen($binary) === 4) {
            // IPv4: Convert to IPv4-mapped IPv6 format (::ffff:0:0/96)
            return str_repeat("\x00", 10) . "\xff\xff" . $binary;
        }

        if (strlen($binary) === 16) {
            // IPv6: Use as is
            return $binary;
        }

        throw new InvalidArgumentException('Invalid IP address length');
    }

    /**
     * Convert a 16-byte representation back to an IP address.
     *
     * @param string $bytes16 The 16-byte representation to convert
     * @return string The IP address (IPv4 or IPv6)
     * @throws InvalidArgumentException If the input length is invalid
     * @throws RuntimeException If conversion fails
     */
    public static function bytesToIp(string $bytes16): string
    {
        if (strlen($bytes16) !== 16) {
            throw new InvalidArgumentException('Input must be 16 bytes');
        }

        // Check for IPv4-mapped IPv6 format
        if (
            substr($bytes16, 0, 10) === str_repeat("\x00", 10) &&
            substr($bytes16, 10, 2) === "\xff\xff"
        ) {
            $ipv4_bytes = substr($bytes16, 12, 4);
            $ip = inet_ntop($ipv4_bytes);
            if ($ip === false) {
                throw new RuntimeException('Failed to convert bytes to IPv4 address');
            }
            return $ip;
        }

        $ip = inet_ntop($bytes16);
        if ($ip === false) {
            throw new RuntimeException('Failed to convert bytes to IPv6 address');
        }
        return $ip;
    }

    /**
     * XOR two strings byte by byte.
     *
     * @param string $a First string
     * @param string $b Second string
     * @return string Result of XOR operation
     */
    protected static function xorStrings(string $a, string $b): string
    {
        $result = '';
        for ($i = 0; $i < strlen($a); $i++) {
            $result .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $result;
    }

    /**
     * Encrypt multiple IP addresses.
     *
     * @param array<string> $ips Array of IP addresses to encrypt
     * @param string $key Encryption key
     * @return array<string> Array of encrypted values
     * @throws InvalidArgumentException If any input is invalid
     * @throws RuntimeException If encryption fails
     */
    abstract public static function encryptBatch(array $ips, string $key): array;

    /**
     * Decrypt multiple encrypted values.
     *
     * @param array<string> $encrypted Array of encrypted values to decrypt
     * @param string $key Decryption key
     * @return array<string> Array of decrypted IP addresses
     * @throws InvalidArgumentException If any input is invalid
     * @throws RuntimeException If decryption fails
     */
    abstract public static function decryptBatch(array $encrypted, string $key): array;
}

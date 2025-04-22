<?php

declare(strict_types=1);

namespace Ipcrypt;

use InvalidArgumentException;
use RuntimeException;

/**
 * Implementation of ipcrypt-deterministic using AES-128.
 *
 * This implementation provides deterministic encryption of IP addresses.
 * The same input will always produce the same output when using the same key.
 *
 * Features:
 * - Fixed output size (16 bytes)
 * - Format-preserving for IPv4/IPv6
 * - Batch processing support
 * - Suitable for database indexing and lookup operations
 */
class IpcryptDeterministic extends AbstractIpcrypt
{
    /**
     * Generate a random 16-byte key suitable for use with this implementation.
     *
     * @return string A 16-byte random key
     * @throws RuntimeException If secure random number generation fails
     */
    public static function generateKey(): string
    {
        return random_bytes(16);
    }

    /**
     * Convert an IP address to its 16-byte representation
     */
    public static function ipToBytes(string $ip): string
    {
        $binary = inet_pton($ip);
        if ($binary === false) {
            throw new InvalidArgumentException("Invalid IP address");
        }

        if (strlen($binary) === 4) {
            // IPv4: Convert to IPv4-mapped IPv6 format (::ffff:0:0/96)
            return str_repeat("\x00", 10) . "\xff\xff" . $binary;
        }

        if (strlen($binary) === 16) {
            // IPv6: Use as is
            return $binary;
        }

        throw new InvalidArgumentException("Invalid IP address length");
    }

    /**
     * Convert a 16-byte representation back to an IP address
     */
    public static function bytesToIp(string $bytes16): string
    {
        if (strlen($bytes16) !== 16) {
            throw new InvalidArgumentException("Input must be 16 bytes");
        }

        // Check for IPv4-mapped IPv6 format
        if (
            substr($bytes16, 0, 10) === str_repeat("\x00", 10) &&
            substr($bytes16, 10, 2) === "\xff\xff"
        ) {
            $ipv4_bytes = substr($bytes16, 12, 4);
            $ip = inet_ntop($ipv4_bytes);
            if ($ip === false) {
                throw new RuntimeException("Failed to convert bytes to IPv4 address");
            }
            return $ip;
        }

        $ip = inet_ntop($bytes16);
        if ($ip === false) {
            throw new RuntimeException("Failed to convert bytes to IPv6 address");
        }
        return $ip;
    }

    /**
     * Encrypt an IP address using AES-128.
     *
     * @param string $ip The IP address to encrypt
     * @param string $key The 16-byte encryption key
     * @return string The encrypted IP address
     * @throws InvalidArgumentException If the key length is invalid
     * @throws RuntimeException If encryption fails
     */
    public static function encrypt(string $ip, string $key): string
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        $plaintext = self::ipToBytes($ip);
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-128-ecb',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed');
        }

        return self::bytesToIp($ciphertext);
    }

    /**
     * Decrypt an IP address using AES-128.
     *
     * @param string $ip The encrypted IP address
     * @param string $key The 16-byte decryption key
     * @return string The decrypted IP address
     * @throws InvalidArgumentException If the key length is invalid
     * @throws RuntimeException If decryption fails
     */
    public static function decrypt(string $ip, string $key): string
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        $ciphertext = self::ipToBytes($ip);
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-128-ecb',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );

        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed');
        }

        return self::bytesToIp($plaintext);
    }

    /**
     * Encrypt multiple IP addresses using AES-128.
     *
     * @param array $ips Array of IP addresses to encrypt
     * @param string $key The 16-byte encryption key
     * @return array Array of encrypted IP addresses
     * @throws InvalidArgumentException If the key length is invalid or any IP is invalid
     * @throws RuntimeException If encryption fails
     */
    public static function encryptBatch(array $ips, string $key): array
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        $result = [];
        foreach ($ips as $ip) {
            $result[] = self::encrypt($ip, $key);
        }
        return $result;
    }

    /**
     * Decrypt multiple IP addresses using AES-128.
     *
     * @param array $encrypted Array of encrypted IP addresses
     * @param string $key The 16-byte decryption key
     * @return array Array of decrypted IP addresses
     * @throws InvalidArgumentException If the key length is invalid or any IP is invalid
     * @throws RuntimeException If decryption fails
     */
    public static function decryptBatch(array $encrypted, string $key): array
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        $result = [];
        foreach ($encrypted as $ip) {
            $result[] = self::decrypt($ip, $key);
        }
        return $result;
    }
}

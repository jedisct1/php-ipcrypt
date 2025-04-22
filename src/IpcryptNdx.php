<?php

declare(strict_types=1);

namespace Ipcrypt;

use InvalidArgumentException;
use RuntimeException;

/**
 * Implementation of ipcrypt-ndx using XTS mode.
 *
 * This implementation uses XTS mode to provide non-deterministic
 * encryption of IP addresses. Each encryption operation uses a tweak
 * value to produce different ciphertexts for the same input.
 *
 * Security Features:
 * - Non-deterministic encryption (different output for same input)
 * - 8-byte random tweak for each encryption
 * - Based on XTS mode with AES-128
 *
 * Output Format:
 * - Total size: 24 bytes
 * - First 8 bytes: tweak
 * - Last 16 bytes: ciphertext
 *
 * Implementation Details:
 * - Uses AES-128 as base cipher
 * - Implements full XTS mode
 * - Supports batch processing
 * - Format-preserving for IPv4/IPv6
 */
class IpcryptNdx extends AbstractIpcrypt
{
    /**
     * Encrypt a block using AES-XTS.
     *
     * For a single block of AES-XTS:
     * 1. Split the key into two halves (K1, K2)
     * 2. Encrypt the tweak with K2 to get ET
     * 3. Encrypt the block as: AES128(block ⊕ ET, K1) ⊕ ET
     *
     * @param string $block The 16-byte block to encrypt
     * @param string $key The 32-byte key (two AES-128 keys)
     * @param string $tweak The 16-byte tweak
     * @return string The encrypted block
     * @throws InvalidArgumentException If input lengths are invalid
     * @throws RuntimeException If encryption fails
     */
    private static function aesXtsEncryptBlock(string $block, string $key, string $tweak): string
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 32 bytes (two AES-128 keys)');
        }
        if (strlen($tweak) !== 16) {
            throw new InvalidArgumentException('Tweak must be 16 bytes');
        }
        if (strlen($block) !== 16) {
            throw new InvalidArgumentException('Block must be 16 bytes');
        }

        // Split the key into two halves
        $k1 = substr($key, 0, 16);
        $k2 = substr($key, 16, 16);

        // Encrypt the tweak with K2
        $et = openssl_encrypt(
            $tweak,
            'aes-128-ecb',
            $k2,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($et === false) {
            throw new RuntimeException('Tweak encryption failed');
        }

        // XOR the block with the encrypted tweak
        $xored = self::xorStrings($block, $et);

        // Encrypt with K1
        $encrypted = openssl_encrypt(
            $xored,
            'aes-128-ecb',
            $k1,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($encrypted === false) {
            throw new RuntimeException('Block encryption failed');
        }

        // Final XOR with the encrypted tweak
        return self::xorStrings($encrypted, $et);
    }

    /**
     * Decrypt a block using AES-XTS.
     *
     * For a single block of AES-XTS:
     * 1. Split the key into two halves (K1, K2)
     * 2. Encrypt the tweak with K2 to get ET
     * 3. Decrypt the block as: AES128⁻¹(block ⊕ ET, K1) ⊕ ET
     *
     * @param string $block The 16-byte block to decrypt
     * @param string $key The 32-byte key (two AES-128 keys)
     * @param string $tweak The 16-byte tweak
     * @return string The decrypted block
     * @throws InvalidArgumentException If input lengths are invalid
     * @throws RuntimeException If decryption fails
     */
    private static function aesXtsDecryptBlock(string $block, string $key, string $tweak): string
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 32 bytes (two AES-128 keys)');
        }
        if (strlen($tweak) !== 16) {
            throw new InvalidArgumentException('Tweak must be 16 bytes');
        }
        if (strlen($block) !== 16) {
            throw new InvalidArgumentException('Block must be 16 bytes');
        }

        // Split the key into two halves
        $k1 = substr($key, 0, 16);
        $k2 = substr($key, 16, 16);

        // Encrypt the tweak with K2
        $et = openssl_encrypt(
            $tweak,
            'aes-128-ecb',
            $k2,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($et === false) {
            throw new RuntimeException('Tweak encryption failed');
        }

        // XOR the block with the encrypted tweak
        $xored = self::xorStrings($block, $et);

        // Decrypt with K1
        $decrypted = openssl_decrypt(
            $xored,
            'aes-128-ecb',
            $k1,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($decrypted === false) {
            throw new RuntimeException('Block decryption failed');
        }

        // Final XOR with the encrypted tweak
        return self::xorStrings($decrypted, $et);
    }

    /**
     * Encrypt an IP address using AES-XTS.
     *
     * @param string $ip The IP address to encrypt
     * @param string $key The 32-byte encryption key (two AES-128 keys)
     * @param string|null $tweak Optional 16-byte tweak (random if not provided)
     * @return string The 32-byte result (16-byte tweak || 16-byte ciphertext)
     * @throws InvalidArgumentException If inputs are invalid
     * @throws RuntimeException If encryption fails
     */
    public static function encrypt(string $ip, string $key, ?string $tweak = null): string
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 32 bytes (two AES-128 keys)');
        }

        // Generate a random 16-byte tweak if not provided
        if ($tweak === null) {
            $tweak = random_bytes(16);
        } elseif (strlen($tweak) !== 16) {
            throw new InvalidArgumentException('Tweak must be 16 bytes');
        }

        $plaintext = self::ipToBytes($ip);
        $ciphertext = self::aesXtsEncryptBlock($plaintext, $key, $tweak);

        // Return tweak || ciphertext
        return $tweak . $ciphertext;
    }

    /**
     * Decrypt an IP address using AES-XTS.
     *
     * @param string $encrypted The 32-byte encrypted data (16-byte tweak || 16-byte ciphertext)
     * @param string $key The 32-byte decryption key (two AES-128 keys)
     * @return string The decrypted IP address
     * @throws InvalidArgumentException If inputs are invalid
     * @throws RuntimeException If decryption fails
     */
    public static function decrypt(string $encrypted, string $key): string
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 32 bytes (two AES-128 keys)');
        }
        if (strlen($encrypted) !== 32) {
            throw new InvalidArgumentException('Encrypted data must be 32 bytes');
        }

        // Split into tweak and ciphertext
        $tweak = substr($encrypted, 0, 16);
        $ciphertext = substr($encrypted, 16, 16);

        $plaintext = self::aesXtsDecryptBlock($ciphertext, $key, $tweak);
        return self::bytesToIp($plaintext);
    }

    /**
     * Generate a random 32-byte key suitable for use with this implementation.
     * The key consists of two 16-byte AES-128 keys concatenated together.
     *
     * @return string A 32-byte random key (two AES-128 keys)
     * @throws RuntimeException If secure random number generation fails
     */
    public static function generateKey(): string
    {
        return random_bytes(32);
    }

    /**
     * Encrypt multiple IP addresses using AES-XTS.
     * A random tweak is generated for each IP address.
     *
     * @param array<string> $ips Array of IP addresses to encrypt
     * @param string $key The 32-byte encryption key (two AES-128 keys)
     * @return array<string> Array of encrypted values (each 32 bytes: 16-byte tweak || 16-byte ciphertext)
     * @throws InvalidArgumentException If the key length is invalid or any IP is invalid
     * @throws RuntimeException If encryption fails
     */
    public static function encryptBatch(array $ips, string $key): array
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 32 bytes (two AES-128 keys)');
        }

        $result = [];
        foreach ($ips as $ip) {
            $result[] = self::encrypt($ip, $key);
        }
        return $result;
    }

    /**
     * Decrypt multiple encrypted values using AES-XTS.
     *
     * @param array<string> $encrypted Array of encrypted values (each 32 bytes: 16-byte tweak || 16-byte ciphertext)
     * @param string $key The 32-byte decryption key (two AES-128 keys)
     * @return array<string> Array of decrypted IP addresses
     * @throws InvalidArgumentException If the key length is invalid or any encrypted value is invalid
     * @throws RuntimeException If decryption fails
     */
    public static function decryptBatch(array $encrypted, string $key): array
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 32 bytes (two AES-128 keys)');
        }

        $result = [];
        foreach ($encrypted as $enc) {
            $result[] = self::decrypt($enc, $key);
        }
        return $result;
    }
}

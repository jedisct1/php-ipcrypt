<?php

declare(strict_types=1);

namespace Ipcrypt;

use InvalidArgumentException;
use RuntimeException;

/**
 * Implementation of ipcrypt-nd using KIASU-BC.
 *
 * This implementation uses KIASU-BC to provide non-deterministic
 * encryption of IP addresses. Each encryption operation uses a tweak
 * value to produce different ciphertexts for the same input.
 *
 * Security Features:
 * - Non-deterministic encryption (different output for same input)
 * - 8-byte random tweak for each encryption
 * - Based on KIASU-BC (tweakable block cipher)
 *
 * Output Format:
 * - Total size: 24 bytes
 * - First 8 bytes: tweak
 * - Last 16 bytes: ciphertext
 *
 * Implementation Details:
 * - Uses AES-128 as base cipher
 * - Implements full KIASU-BC algorithm
 * - Supports batch processing
 * - Format-preserving for IPv4/IPv6
 */
class IpcryptNd extends AbstractIpcrypt
{
    /** @var array<int> AES S-box */
    private const SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];

    /** @var array<int> AES inverse S-box */
    private const INV_SBOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ];

    /** @var array<int> AES round constants */
    private const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    /**
     * Pad an 8-byte tweak to 16 bytes according to KIASU-BC specification.
     *
     * @param string $tweak The 8-byte tweak to pad
     * @return string The padded 16-byte tweak
     * @throws InvalidArgumentException If tweak length is invalid
     */
    private static function padTweak(string $tweak): string
    {
        if (strlen($tweak) !== 8) {
            throw new InvalidArgumentException('Tweak must be 8 bytes');
        }

        $result = '';
        for ($i = 0; $i < 4; $i++) {
            $result .= substr($tweak, $i * 2, 2) . "\x00\x00";
        }
        return $result;
    }

    /**
     * Perform AES SubBytes operation.
     *
     * @param string $state The current state
     * @param bool $inverse Whether to use inverse S-box
     * @return string The transformed state
     */
    private static function subBytes(string $state, bool $inverse = false): string
    {
        $sbox = $inverse ? self::INV_SBOX : self::SBOX;
        $bytes = str_split($state);
        $result = '';
        foreach ($bytes as $byte) {
            $result .= chr($sbox[ord($byte)]);
        }
        return $result;
    }

    /**
     * Perform AES ShiftRows operation.
     *
     * @param string $state The current state
     * @param bool $inverse Whether to perform inverse operation
     * @return string The transformed state
     */
    private static function shiftRows(string $state, bool $inverse = false): string
    {
        $indices = $inverse ? [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
                          : [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

        $result = '';
        foreach ($indices as $i) {
            $result .= $state[$i];
        }
        return $result;
    }

    /**
     * Perform AES MixColumns operation.
     *
     * @param string $state The current state
     * @param bool $inverse Whether to perform inverse operation
     * @return string The transformed state
     */
    private static function mixColumns(string $state, bool $inverse = false): string
    {
        $result = '';
        for ($i = 0; $i < 4; $i++) {
            $s0 = ord($state[$i * 4]);
            $s1 = ord($state[$i * 4 + 1]);
            $s2 = ord($state[$i * 4 + 2]);
            $s3 = ord($state[$i * 4 + 3]);

            if (!$inverse) {
                $result .= chr(self::mul2($s0) ^ self::mul3($s1) ^ $s2 ^ $s3);
                $result .= chr($s0 ^ self::mul2($s1) ^ self::mul3($s2) ^ $s3);
                $result .= chr($s0 ^ $s1 ^ self::mul2($s2) ^ self::mul3($s3));
                $result .= chr(self::mul3($s0) ^ $s1 ^ $s2 ^ self::mul2($s3));
            } else {
                $result .= chr(self::mul14($s0) ^ self::mul11($s1) ^ self::mul13($s2) ^ self::mul9($s3));
                $result .= chr(self::mul9($s0) ^ self::mul14($s1) ^ self::mul11($s2) ^ self::mul13($s3));
                $result .= chr(self::mul13($s0) ^ self::mul9($s1) ^ self::mul14($s2) ^ self::mul11($s3));
                $result .= chr(self::mul11($s0) ^ self::mul13($s1) ^ self::mul9($s2) ^ self::mul14($s3));
            }
        }
        return $result;
    }

    /**
     * Multiply by 2 in GF(2^8).
     *
     * @param int $x Value to multiply
     * @return int Result of multiplication
     */
    private static function mul2(int $x): int
    {
        return (($x << 1) & 0xFF) ^ (($x & 0x80) ? 0x1B : 0);
    }

    /**
     * Multiply by 3 in GF(2^8).
     *
     * @param int $x Value to multiply
     * @return int Result of multiplication
     */
    private static function mul3(int $x): int
    {
        return self::mul2($x) ^ $x;
    }

    /**
     * Higher-order multiplication in GF(2^8).
     *
     * @param int $x Value to multiply
     * @param int $n Multiplier
     * @return int Result of multiplication
     */
    private static function mulN(int $x, int $n): int
    {
        $result = 0;
        $t = $x;
        while ($n > 0) {
            if ($n & 1) {
                $result ^= $t;
            }
            $t = self::mul2($t);
            $n >>= 1;
        }
        return $result;
    }

    private static function mul9(int $x): int
    {
        return self::mulN($x, 9);
    }
    private static function mul11(int $x): int
    {
        return self::mulN($x, 11);
    }
    private static function mul13(int $x): int
    {
        return self::mulN($x, 13);
    }
    private static function mul14(int $x): int
    {
        return self::mulN($x, 14);
    }

    /**
     * Generate AES round keys.
     *
     * @param string $key The 16-byte key
     * @return array<int, string> Array of round keys
     * @throws InvalidArgumentException If key length is invalid
     */
    private static function expandKey(string $key): array
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        $round_keys = [$key];
        for ($i = 0; $i < 10; $i++) {
            $prev_key = $round_keys[$i];

            // RotWord
            $temp = substr($prev_key, -4);
            $temp = substr($temp, 1) . $temp[0];

            // SubWord
            $temp = self::subBytes($temp);

            // XOR with RCON
            $temp[0] = chr(ord($temp[0]) ^ self::RCON[$i]);

            $new_key = '';
            for ($j = 0; $j < 4; $j++) {
                $word = substr($prev_key, $j * 4, 4);
                if ($j === 0) {
                    $word = self::xorStrings($word, $temp);
                } else {
                    $word = self::xorStrings($word, substr($new_key, ($j - 1) * 4, 4));
                }
                $new_key .= $word;
            }
            $round_keys[] = $new_key;
        }

        return $round_keys;
    }

    /**
     * Encrypt a block using KIASU-BC.
     *
     * @param string $key The 16-byte key
     * @param string $tweak The 8-byte tweak
     * @param string $plaintext The 16-byte plaintext
     * @return string The 16-byte ciphertext
     * @throws InvalidArgumentException If input lengths are invalid
     */
    private static function kiasuBcEncrypt(string $key, string $tweak, string $plaintext): string
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }
        if (strlen($tweak) !== 8) {
            throw new InvalidArgumentException('Tweak must be 8 bytes');
        }
        if (strlen($plaintext) !== 16) {
            throw new InvalidArgumentException('Plaintext must be 16 bytes');
        }

        $round_keys = self::expandKey($key);
        $padded_tweak = self::padTweak($tweak);

        // Initial round
        $state = self::xorStrings(self::xorStrings($plaintext, $round_keys[0]), $padded_tweak);

        // Main rounds
        for ($i = 1; $i < 10; $i++) {
            $state = self::subBytes($state);
            $state = self::shiftRows($state);
            $state = self::mixColumns($state);
            $state = self::xorStrings(self::xorStrings($state, $round_keys[$i]), $padded_tweak);
        }

        // Final round
        $state = self::subBytes($state);
        $state = self::shiftRows($state);
        $state = self::xorStrings(self::xorStrings($state, $round_keys[10]), $padded_tweak);

        return $state;
    }

    /**
     * Decrypt a block using KIASU-BC.
     *
     * @param string $key The 16-byte key
     * @param string $tweak The 8-byte tweak
     * @param string $ciphertext The 16-byte ciphertext
     * @return string The 16-byte plaintext
     * @throws InvalidArgumentException If input lengths are invalid
     */
    private static function kiasuBcDecrypt(string $key, string $tweak, string $ciphertext): string
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }
        if (strlen($tweak) !== 8) {
            throw new InvalidArgumentException('Tweak must be 8 bytes');
        }
        if (strlen($ciphertext) !== 16) {
            throw new InvalidArgumentException('Ciphertext must be 16 bytes');
        }

        $round_keys = self::expandKey($key);
        $padded_tweak = self::padTweak($tweak);

        // Initial round
        $state = self::xorStrings(self::xorStrings($ciphertext, $round_keys[10]), $padded_tweak);
        $state = self::shiftRows($state, true);
        $state = self::subBytes($state, true);

        // Main rounds
        for ($i = 9; $i > 0; $i--) {
            $state = self::xorStrings(self::xorStrings($state, $round_keys[$i]), $padded_tweak);
            $state = self::mixColumns($state, true);
            $state = self::shiftRows($state, true);
            $state = self::subBytes($state, true);
        }

        // Final round
        $state = self::xorStrings(self::xorStrings($state, $round_keys[0]), $padded_tweak);

        return $state;
    }

    /**
     * Encrypt an IP address using KIASU-BC.
     *
     * @param string $ip The IP address to encrypt
     * @param string $key The 16-byte encryption key
     * @param string|null $tweak Optional 8-byte tweak (random if not provided)
     * @return string The 24-byte result (8-byte tweak || 16-byte ciphertext)
     * @throws InvalidArgumentException If inputs are invalid
     * @throws RuntimeException If encryption fails
     */
    public static function encrypt(string $ip, string $key, ?string $tweak = null): string
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        // Generate a random 8-byte tweak if not provided
        if ($tweak === null) {
            $tweak = random_bytes(8);
        } elseif (strlen($tweak) !== 8) {
            throw new InvalidArgumentException('Tweak must be 8 bytes');
        }

        $plaintext = self::ipToBytes($ip);
        $ciphertext = self::kiasuBcEncrypt($key, $tweak, $plaintext);

        // Return tweak || ciphertext
        return $tweak . $ciphertext;
    }

    /**
     * Decrypt an IP address using KIASU-BC.
     *
     * @param string $encrypted The 24-byte encrypted data (8-byte tweak || 16-byte ciphertext)
     * @param string $key The 16-byte decryption key
     * @return string The decrypted IP address
     * @throws InvalidArgumentException If inputs are invalid
     * @throws RuntimeException If decryption fails
     */
    public static function decrypt(string $encrypted, string $key): string
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }
        if (strlen($encrypted) !== 24) {
            throw new InvalidArgumentException('Encrypted data must be 24 bytes');
        }

        // Split into tweak and ciphertext
        $tweak = substr($encrypted, 0, 8);
        $ciphertext = substr($encrypted, 8, 16);

        $plaintext = self::kiasuBcDecrypt($key, $tweak, $ciphertext);
        return self::bytesToIp($plaintext);
    }

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
     * Encrypt multiple IP addresses using KIASU-BC.
     * A random tweak is generated for each IP address.
     *
     * @param array<string> $ips Array of IP addresses to encrypt
     * @param string $key The 16-byte encryption key
     * @return array<string> Array of encrypted values (each 24 bytes: 8-byte tweak || 16-byte ciphertext)
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
     * Decrypt multiple encrypted values using KIASU-BC.
     *
     * @param array<string> $encrypted Array of encrypted values (each 24 bytes: 8-byte tweak || 16-byte ciphertext)
     * @param string $key The 16-byte decryption key
     * @return array<string> Array of decrypted IP addresses
     * @throws InvalidArgumentException If the key length is invalid or any encrypted value is invalid
     * @throws RuntimeException If decryption fails
     */
    public static function decryptBatch(array $encrypted, string $key): array
    {
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException('Key must be 16 bytes');
        }

        $result = [];
        foreach ($encrypted as $enc) {
            $result[] = self::decrypt($enc, $key);
        }
        return $result;
    }
}

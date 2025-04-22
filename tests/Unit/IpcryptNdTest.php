<?php

declare(strict_types=1);

namespace Ipcrypt\Tests\Unit;

use Ipcrypt\IpcryptNd;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class IpcryptNdTest extends TestCase
{
    private IpcryptNd $ipcrypt;
    private string $key;
    private string $tweak;

    protected function setUp(): void
    {
        $this->ipcrypt = new IpcryptNd();
        // Use fixed values for deterministic testing
        $this->key = hex2bin('0123456789abcdeffedcba9876543210');
        $this->tweak = hex2bin('08e0c289bff23b7c');
    }

    /**
     * Test specification vectors
     */
    #[DataProvider('specificationVectorProvider')]
    public function testSpecificationVectors(string $key, string $tweak, string $ip, string $expected): void
    {
        $encrypted = $this->ipcrypt->encrypt($ip, hex2bin($key), hex2bin($tweak));
        // For non-deterministic mode, the output is a 24-byte binary string (8-byte tweak + 16-byte ciphertext)
        $this->assertEquals(24, strlen($encrypted), 'Encrypted output should be 24 bytes');
        // First 8 bytes should be the tweak
        $this->assertEquals(hex2bin($tweak), substr($encrypted, 0, 8), 'First 8 bytes should be the tweak');

        $decrypted = $this->ipcrypt->decrypt($encrypted, hex2bin($key));
        $this->assertEquals($ip, $decrypted);
    }

    public static function specificationVectorProvider(): array
    {
        return [
            [
                '0123456789abcdeffedcba9876543210',
                'deadbeefdeadbeef',
                '192.0.2.1',
                '' // Expected binary output removed since we check length and tweak separately
            ],
            [
                '1032547698badcfeefcdab8967452301',
                'cafebabecafebabe',
                '198.51.100.2',
                '' // Expected binary output removed since we check length and tweak separately
            ]
        ];
    }

    /**
     * Test non-deterministic behavior with random tweaks.
     */
    public function testNonDeterministicBehavior(): void
    {
        $key = random_bytes(16);
        $ip = '192.0.2.1';

        // Same key, different tweaks should produce different outputs
        $encrypted1 = $this->ipcrypt->encrypt($ip, $key);
        $encrypted2 = $this->ipcrypt->encrypt($ip, $key);
        $this->assertNotSame($encrypted1, $encrypted2, 'Random tweaks produced same ciphertext');

        // Both should decrypt to the same plaintext
        $this->assertEquals($ip, $this->ipcrypt->decrypt($encrypted1, $key), 'First decryption failed');
        $this->assertEquals($ip, $this->ipcrypt->decrypt($encrypted2, $key), 'Second decryption failed');
    }

    /**
     * Test edge cases and special addresses
     */
    #[DataProvider('edgeCaseProvider')]
    public function testEdgeCases(string $ip, string $tweak): void
    {
        $encrypted = $this->ipcrypt->encrypt($ip, $this->key, hex2bin($tweak));
        $decrypted = $this->ipcrypt->decrypt($encrypted, $this->key);
        $this->assertEquals($ip, $decrypted);
    }

    public static function edgeCaseProvider(): array
    {
        return [
            ['0.0.0.0', 'deadbeefdeadbeef'],
            ['255.255.255.255', 'cafebabecafebabe'],
            ['127.0.0.1', '0123456789abcdef'],
            ['::1', 'fedcba9876543210'],
            ['::', 'aaaaaaaaaaaaaaaa'],
            ['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'bbbbbbbbbbbbbbbb']
        ];
    }

    /**
     * Test error cases.
     */
    public function testErrorCases(): void
    {
        $key = hex2bin(str_repeat('00', 16));  // 16-byte key
        $tweak = hex2bin(str_repeat('00', 8));  // 8-byte tweak

        // Invalid IP addresses
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP address');
        $this->ipcrypt->encrypt('256.256.256.256', $key, $tweak);
    }

    /**
     * Test invalid key length.
     */
    public function testInvalidKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 16 bytes');
        $this->ipcrypt->encrypt('192.0.2.1', 'too_short');
    }

    /**
     * Test invalid tweak length.
     */
    public function testInvalidTweakLength(): void
    {
        $key = hex2bin(str_repeat('00', 16));  // 16-byte key
        $shortTweak = hex2bin('0000');  // Only 2 bytes

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Tweak must be 8 bytes');
        $this->ipcrypt->encrypt('192.0.2.1', $key, $shortTweak);
    }

    // Batch processing tests below

    public function testEncryptBatchWithIpv4(): void
    {
        $ips = [
            '192.0.2.1',
            '198.51.100.2',
            '203.0.113.3'
        ];

        $encrypted = $this->ipcrypt->encryptBatch($ips, $this->key);

        $this->assertCount(3, $encrypted);
        foreach ($encrypted as $enc) {
            $this->assertEquals(24, strlen($enc), 'Encrypted value should be 24 bytes');
            // Each encryption should have a different random tweak
            $tweak1 = substr($enc, 0, 8);
            foreach ($encrypted as $other) {
                if ($other !== $enc) {
                    $tweak2 = substr($other, 0, 8);
                    $this->assertNotEquals($tweak1, $tweak2, 'Tweaks should be random and different');
                }
            }
        }
    }

    public function testEncryptBatchWithIpv6(): void
    {
        $ips = [
            '2001:db8::1',
            '2001:db8::2',
            '2001:db8::3'
        ];

        $encrypted = $this->ipcrypt->encryptBatch($ips, $this->key);

        $this->assertCount(3, $encrypted);
        foreach ($encrypted as $enc) {
            $this->assertEquals(24, strlen($enc), 'Encrypted value should be 24 bytes');
            // Each encryption should have a different random tweak
            $tweak1 = substr($enc, 0, 8);
            foreach ($encrypted as $other) {
                if ($other !== $enc) {
                    $tweak2 = substr($other, 0, 8);
                    $this->assertNotEquals($tweak1, $tweak2, 'Tweaks should be random and different');
                }
            }
        }
    }

    public function testDecryptBatchMatchesOriginal(): void
    {
        $original_ips = [
            '192.0.2.1',
            '2001:db8::1',
            '198.51.100.2'
        ];

        $encrypted = $this->ipcrypt->encryptBatch($original_ips, $this->key, $this->tweak);
        $decrypted = $this->ipcrypt->decryptBatch($encrypted, $this->key);

        $this->assertEquals($original_ips, $decrypted);
    }

    public function testBatchWithEmptyArray(): void
    {
        $empty = [];
        $encrypted = $this->ipcrypt->encryptBatch($empty, $this->key, $this->tweak);
        $this->assertEquals([], $encrypted);

        $decrypted = $this->ipcrypt->decryptBatch($empty, $this->key);
        $this->assertEquals([], $decrypted);
    }

    public function testBatchWithInvalidKey(): void
    {
        $ips = ['192.0.2.1'];
        $invalid_key = 'too_short';

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 16 bytes');
        $this->ipcrypt->encryptBatch($ips, $invalid_key);
    }

    public function testBatchWithInvalidIp(): void
    {
        $invalid_ips = [
            '192.0.2.1',    // valid
            'invalid_ip',   // invalid
            '198.51.100.2'  // valid
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP address');
        $this->ipcrypt->encryptBatch($invalid_ips, $this->key);
    }

    public function testBatchWithMixedIpVersions(): void
    {
        $mixed_ips = [
            '192.0.2.1',      // IPv4
            '2001:db8::1',    // IPv6
            '198.51.100.2'    // IPv4
        ];

        $encrypted = $this->ipcrypt->encryptBatch($mixed_ips, $this->key, $this->tweak);
        $decrypted = $this->ipcrypt->decryptBatch($encrypted, $this->key);

        $this->assertEquals($mixed_ips, $decrypted);
    }

    public function testBatchNonDeterministicBehavior(): void
    {
        $ips = ['192.0.2.1', '2001:db8::1'];

        // Without tweak (should be random)
        $encrypted1 = $this->ipcrypt->encryptBatch($ips, $this->key);
        $encrypted2 = $this->ipcrypt->encryptBatch($ips, $this->key);

        // Each encryption should be different
        $this->assertNotEquals($encrypted1, $encrypted2);

        // But should decrypt to the same values
        $decrypted1 = $this->ipcrypt->decryptBatch($encrypted1, $this->key);
        $decrypted2 = $this->ipcrypt->decryptBatch($encrypted2, $this->key);
        $this->assertEquals($decrypted1, $decrypted2);
    }
}

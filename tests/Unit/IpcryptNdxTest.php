<?php

declare(strict_types=1);

namespace Ipcrypt\Tests\Unit;

use Ipcrypt\IpcryptNdx;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class IpcryptNdxTest extends TestCase
{
    private IpcryptNdx $ipcrypt;
    private string $key;
    private string $tweak;

    protected function setUp(): void
    {
        $this->ipcrypt = new IpcryptNdx();
        // Use fixed key for deterministic testing (32 bytes for XTS mode)
        $this->key = hex2bin('0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210');
        $this->tweak = hex2bin(str_repeat('ff', 16));  // 16-byte tweak
    }

    /**
     * Test specification vectors
     */
    #[DataProvider('specificationVectorProvider')]
    public function testSpecificationVectors(string $key, string $tweak, string $ip, string $expected): void
    {
        $encrypted = $this->ipcrypt->encrypt($ip, hex2bin($key), hex2bin($tweak));
        $this->assertEquals(32, strlen($encrypted), 'Encrypted output should be 32 bytes');
        $this->assertEquals(hex2bin($tweak), substr($encrypted, 0, 16), 'First 16 bytes should be the tweak');

        $decrypted = $this->ipcrypt->decrypt($encrypted, hex2bin($key));
        $this->assertEquals($ip, $decrypted);
    }

    public static function specificationVectorProvider(): array
    {
        return [
            [
                '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210',
                'deadbeefdeadbeefdeadbeefdeadbeef',
                '192.0.2.1',
                ''
            ],
            [
                '1032547698badcfeefcdab89674523011032547698badcfeefcdab8967452301',
                'cafebabecafebabecafebabecafebabe',
                '198.51.100.2',
                ''
            ]
        ];
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
            ['0.0.0.0', 'deadbeefdeadbeefdeadbeefdeadbeef'],
            ['255.255.255.255', 'cafebabecafebabecafebabecafebabe'],
            ['127.0.0.1', '0123456789abcdef0123456789abcdef'],
            ['::1', 'fedcba9876543210fedcba9876543210'],
            ['::', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
            ['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']
        ];
    }

    /**
     * Test non-deterministic behavior with random tweaks.
     */
    public function testNonDeterministicBehavior(): void
    {
        $key = IpcryptNdx::generateKey();
        $ip = '192.0.2.1';

        // Same key, different tweaks should produce different outputs
        $ciphertext1 = IpcryptNdx::encrypt($ip, $key);
        $ciphertext2 = IpcryptNdx::encrypt($ip, $key);
        $this->assertNotSame($ciphertext1, $ciphertext2, 'Random tweaks produced same ciphertext');

        // Both should decrypt to the same plaintext
        $this->assertSame($ip, IpcryptNdx::decrypt($ciphertext1, $key), 'First decryption failed');
        $this->assertSame($ip, IpcryptNdx::decrypt($ciphertext2, $key), 'Second decryption failed');
    }

    /**
     * Test error cases.
     */
    public function testErrorCases(): void
    {
        $key = hex2bin(str_repeat('00', 32));  // 32-byte key
        $tweak = hex2bin(str_repeat('00', 16));  // 16-byte tweak

        // Invalid IP addresses
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP address');
        IpcryptNdx::encrypt('256.256.256.256', $key, $tweak);
    }

    /**
     * Test invalid key length.
     */
    public function testInvalidKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 32 bytes');
        IpcryptNdx::encrypt('192.0.2.1', 'too_short');
    }

    /**
     * Test invalid tweak length.
     */
    public function testInvalidTweakLength(): void
    {
        $key = hex2bin(str_repeat('00', 32));  // 32-byte key
        $shortTweak = hex2bin('0000');  // Only 2 bytes

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Tweak must be 16 bytes');
        IpcryptNdx::encrypt('192.0.2.1', $key, $shortTweak);
    }

    // Batch processing tests below

    public function testEncryptBatchWithIpv4(): void
    {
        $ips = [
            '192.0.2.1',
            '198.51.100.2',
            '203.0.113.3'
        ];

        $encrypted = IpcryptNdx::encryptBatch($ips, $this->key);

        $this->assertCount(3, $encrypted);
        foreach ($encrypted as $enc) {
            $this->assertEquals(32, strlen($enc), 'Encrypted value should be 32 bytes');
            // Each encryption should have a different random tweak
            $tweak1 = substr($enc, 0, 16);
            foreach ($encrypted as $other) {
                if ($other !== $enc) {
                    $tweak2 = substr($other, 0, 16);
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

        $encrypted = IpcryptNdx::encryptBatch($ips, $this->key);

        $this->assertCount(3, $encrypted);
        foreach ($encrypted as $enc) {
            $this->assertEquals(32, strlen($enc), 'Encrypted value should be 32 bytes');
            // Each encryption should have a different random tweak
            $tweak1 = substr($enc, 0, 16);
            foreach ($encrypted as $other) {
                if ($other !== $enc) {
                    $tweak2 = substr($other, 0, 16);
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

        $encrypted = IpcryptNdx::encryptBatch($original_ips, $this->key, $this->tweak);
        $decrypted = IpcryptNdx::decryptBatch($encrypted, $this->key);

        $this->assertEquals($original_ips, $decrypted);
    }

    public function testBatchWithEmptyArray(): void
    {
        $empty = [];
        $encrypted = IpcryptNdx::encryptBatch($empty, $this->key, $this->tweak);
        $this->assertEquals([], $encrypted);

        $decrypted = IpcryptNdx::decryptBatch($empty, $this->key);
        $this->assertEquals([], $decrypted);
    }

    public function testBatchWithInvalidKey(): void
    {
        $ips = ['192.0.2.1'];
        $invalid_key = 'too_short';

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 32 bytes');
        IpcryptNdx::encryptBatch($ips, $invalid_key);
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
        IpcryptNdx::encryptBatch($invalid_ips, $this->key);
    }

    public function testBatchWithMixedIpVersions(): void
    {
        $mixed_ips = [
            '192.0.2.1',      // IPv4
            '2001:db8::1',    // IPv6
            '198.51.100.2'    // IPv4
        ];

        $encrypted = IpcryptNdx::encryptBatch($mixed_ips, $this->key, $this->tweak);
        $decrypted = IpcryptNdx::decryptBatch($encrypted, $this->key);

        $this->assertEquals($mixed_ips, $decrypted);
    }

    public function testBatchNonDeterministicBehavior(): void
    {
        $ips = ['192.0.2.1', '2001:db8::1'];

        // Without tweak (should be random)
        $encrypted1 = IpcryptNdx::encryptBatch($ips, $this->key);
        $encrypted2 = IpcryptNdx::encryptBatch($ips, $this->key);

        // Each encryption should be different
        $this->assertNotEquals($encrypted1, $encrypted2);

        // But should decrypt to the same values
        $decrypted1 = IpcryptNdx::decryptBatch($encrypted1, $this->key);
        $decrypted2 = IpcryptNdx::decryptBatch($encrypted2, $this->key);
        $this->assertEquals($decrypted1, $decrypted2);
    }
}

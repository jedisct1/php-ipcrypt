<?php

declare(strict_types=1);

namespace Ipcrypt\Tests\Unit;

use Ipcrypt\IpcryptDeterministic;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Test suite for the deterministic IPcrypt implementation.
 * Includes specification test vectors, batch processing tests,
 * edge cases, and error handling.
 */
class IpcryptDeterministicTest extends TestCase
{
    private IpcryptDeterministic $ipcrypt;
    private string $key;

    protected function setUp(): void
    {
        $this->ipcrypt = new IpcryptDeterministic();
        // Use fixed key for deterministic testing
        $this->key = hex2bin('0123456789abcdeffedcba9876543210');
    }

    /**
     * Test specification vectors for IPv4 addresses
     */
    #[DataProvider('standardIpv4Provider')]
    public function testStandardIpv4(string $key, string $ip, string $expected): void
    {
        $encrypted = $this->ipcrypt->encrypt($ip, hex2bin($key));
        $this->assertEquals($expected, $encrypted);

        $decrypted = $this->ipcrypt->decrypt($encrypted, hex2bin($key));
        $this->assertEquals($ip, $decrypted);
    }

    public static function standardIpv4Provider(): array
    {
        return [
            [
                '0123456789abcdeffedcba9876543210',
                '0.0.0.0',
                'bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb'
            ],
            [
                '1032547698badcfeefcdab8967452301',
                '255.255.255.255',
                'aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8'
            ],
            [
                '2b7e151628aed2a6abf7158809cf4f3c',
                '192.0.2.1',
                '1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777'
            ]
        ];
    }

    /**
     * Test specification vectors for IPv6 addresses
     */
    #[DataProvider('standardIpv6Provider')]
    public function testStandardIpv6(string $key, string $ip, string $expected): void
    {
        $encrypted = $this->ipcrypt->encrypt($ip, hex2bin($key));
        $this->assertEquals($expected, $encrypted);

        $decrypted = $this->ipcrypt->decrypt($encrypted, hex2bin($key));
        // For IPv4-mapped IPv6 addresses, the decrypted result will be in IPv4 format
        $expectedDecrypted = $ip;
        if (strpos($ip, '::ffff:') === 0) {
            $parts = explode(':', $ip);
            $expectedDecrypted = end($parts);
        }
        $this->assertEquals($expectedDecrypted, $decrypted);
    }

    public static function standardIpv6Provider(): array
    {
        return [
            [
                '0123456789abcdeffedcba9876543210',
                '::ffff:0.0.0.0',  // IPv4-mapped IPv6 for 0.0.0.0
                'bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb'
            ],
            [
                '1032547698badcfeefcdab8967452301',
                '::ffff:255.255.255.255',  // IPv4-mapped IPv6 for 255.255.255.255
                'aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8'
            ]
        ];
    }

    /**
     * Test edge cases and special addresses
     */
    #[DataProvider('edgeCaseProvider')]
    public function testEdgeCases(string $ip): void
    {
        $encrypted = $this->ipcrypt->encrypt($ip, $this->key);
        $decrypted = $this->ipcrypt->decrypt($encrypted, $this->key);
        $this->assertEquals($ip, $decrypted);
    }

    public static function edgeCaseProvider(): array
    {
        return [
            ['0.0.0.0'],
            ['255.255.255.255'],
            ['127.0.0.1'],
            ['::1'],
            ['::'],
            ['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
        ];
    }

    public function testErrorCases(): void
    {
        // Test invalid IP addresses
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP address');
        $this->ipcrypt->encrypt('invalid_ip', $this->key);
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 16 bytes');
        $this->ipcrypt->encrypt('192.0.2.1', 'too_short');
    }

    public function testKeyConsistency(): void
    {
        $ip = '192.0.2.1';
        $key1 = random_bytes(16);
        $key2 = random_bytes(16);

        // Same key should produce same output
        $enc1 = $this->ipcrypt->encrypt($ip, $key1);
        $enc2 = $this->ipcrypt->encrypt($ip, $key1);
        $this->assertEquals($enc1, $enc2);

        // Different keys should produce different output
        $enc3 = $this->ipcrypt->encrypt($ip, $key2);
        $this->assertNotEquals($enc1, $enc3);
    }

    public function testEncryptBatchWithIpv4(): void
    {
        $ips = [
            '192.0.2.1',
            '198.51.100.2',
            '203.0.113.3'
        ];

        $encrypted = $this->ipcrypt->encryptBatch($ips, $this->key);
        $this->assertCount(3, $encrypted);

        // Each encryption should be deterministic
        $encrypted2 = $this->ipcrypt->encryptBatch($ips, $this->key);
        $this->assertEquals($encrypted, $encrypted2);

        // Decrypt and verify
        $decrypted = $this->ipcrypt->decryptBatch($encrypted, $this->key);
        $this->assertEquals($ips, $decrypted);
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

        // Each encryption should be deterministic
        $encrypted2 = $this->ipcrypt->encryptBatch($ips, $this->key);
        $this->assertEquals($encrypted, $encrypted2);

        // Decrypt and verify
        $decrypted = $this->ipcrypt->decryptBatch($encrypted, $this->key);
        $this->assertEquals($ips, $decrypted);
    }

    public function testBatchWithEmptyArray(): void
    {
        $empty = [];
        $encrypted = $this->ipcrypt->encryptBatch($empty, $this->key);
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

        $encrypted = $this->ipcrypt->encryptBatch($mixed_ips, $this->key);
        $decrypted = $this->ipcrypt->decryptBatch($encrypted, $this->key);

        $this->assertEquals($mixed_ips, $decrypted);
    }
}

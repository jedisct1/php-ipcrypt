# IPcrypt PHP Implementation

This is a PHP implementation of IPcrypt, which provides methods for encrypting and decrypting IP addresses. The implementation follows the [IPcrypt specification](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) and provides three different encryption modes.

## Features

- Deterministic encryption (using AES-128)
- Non-deterministic encryption (using KIASU-BC)
- XEX-mode encryption (using AES-XTS)
- Support for both IPv4 and IPv6 addresses (with IPv4-mapped IPv6 handling)
- Secure key generation for all modes
- Comprehensive test suite with test vectors from the specification
- PSR-12 compliant code style
- Extensive test coverage for core functionality

## Requirements

- PHP 8.2 or higher
- OpenSSL extension (for AES operations)
- Composer (for installation and development)

## Installation

```sh
composer require ipcrypt/php
```

## Usage

### Deterministic Encryption (ipcrypt-deterministic)

Uses AES-128 to provide deterministic encryption. The same input will always produce the same output when using the same key.

```php
use Ipcrypt\IpcryptDeterministic;

// Generate a random 16-byte key
$key = IpcryptDeterministic::generateKey();

// Example with IPv4
$ipv4 = '192.0.2.1';
$encrypted = IpcryptDeterministic::encrypt($ipv4, $key);
$decrypted = IpcryptDeterministic::decrypt($encrypted, $key);

// Example with IPv6
$ipv6 = '2001:db8::1';
$encrypted = IpcryptDeterministic::encrypt($ipv6, $key);
$decrypted = IpcryptDeterministic::decrypt($encrypted, $key);
```

### Non-deterministic Encryption (ipcrypt-nd)

Uses KIASU-BC to provide non-deterministic encryption. Each encryption operation uses a random tweak value to produce different ciphertexts for the same input.

```php
use Ipcrypt\IpcryptNd;

// Generate a random 16-byte key
$key = IpcryptNd::generateKey();

$ip = '192.0.2.1';

// Each encryption produces a different result
$encrypted1 = IpcryptNd::encrypt($ip, $key);  // Uses random 8-byte tweak
$encrypted2 = IpcryptNd::encrypt($ip, $key);  // Different result
echo $encrypted1 !== $encrypted2; // true

// Both decrypt to the same IP
$decrypted1 = IpcryptNd::decrypt($encrypted1, $key);
$decrypted2 = IpcryptNd::decrypt($encrypted2, $key);
echo $decrypted1 === $decrypted2; // true
```

### XTS-mode Encryption (ipcrypt-ndx)

Uses AES-XTS mode to provide non-deterministic encryption with enhanced security properties. Requires a 32-byte key (two AES-128 keys).

```php
use Ipcrypt\IpcryptNdx;

// Generate a random 32-byte key (two AES-128 keys)
$key = IpcryptNdx::generateKey();

$ip = '192.0.2.1';

// Each encryption produces a different result
$encrypted1 = IpcryptNdx::encrypt($ip, $key);  // Uses random 16-byte tweak
$encrypted2 = IpcryptNdx::encrypt($ip, $key);  // Different result
echo $encrypted1 !== $encrypted2; // true

// Both decrypt to the same IP
$decrypted1 = IpcryptNdx::decrypt($encrypted1, $key);
$decrypted2 = IpcryptNdx::decrypt($encrypted2, $key);
echo $decrypted1 === $decrypted2; // true
```

## Development

### Running Tests

The project includes a comprehensive test suite with test vectors from the IPcrypt specification:

```sh
composer install  # Install dependencies
composer test    # Run PHPUnit tests
```

Current test status: ✅ 60 tests, 137 assertions - all passing

### Examples

Complete working examples can be found in the `examples/` directory.

### Code Style

The code follows PSR-12 coding standards. To check and fix code style:

```sh
composer cs      # Check code style
composer cs-fix  # Automatically fix code style issues
```

### Type Safety

The codebase uses PHP 8.2+ type hints throughout:

- Parameter and return type declarations
- Property type declarations
- Strict type checking enabled
- Comprehensive PHPDoc blocks with type information

## Implementation Details

### IP Address Handling

- IPv4 addresses are converted to IPv4-mapped IPv6 addresses internally
- All operations work on 16-byte blocks (IPv6 address size)
- Automatic detection and conversion between IPv4 and IPv6 formats

### Security Features

- Built-in secure key generation for each mode
- Secure random number generation for tweaks
- No padding required (fixed-size inputs)
- Constant-time operations where possible
- Input validation for all parameters
- Regular security scans via GitHub Actions

### Key Generation

Each implementation provides a secure key generation method:

- `IpcryptDeterministic::generateKey()`: Generates a 16-byte key for AES-128
- `IpcryptNd::generateKey()`: Generates a 16-byte key for KIASU-BC
- `IpcryptNdx::generateKey()`: Generates a 32-byte key (two AES-128 keys) for XTS mode

### Continuous Integration

The project uses GitHub Actions for:

- Automated testing on various PHP versions
- Code style checking (PSR-12)
- Security vulnerability scanning
- Test coverage reporting

## License

MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

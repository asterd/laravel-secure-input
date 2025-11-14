# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- File upload security checks with dangerous extension blocking
- Enhanced SQL injection pattern detection
- Enhanced RCE (Remote Code Execution) pattern detection
- Additional XSS protection patterns
- Support for Laravel 12 middleware registration structure
- Configuration options for file upload security

### Changed
- Removed GET method from default excluded methods to process GET parameters
- Updated documentation with Laravel 12 installation instructions
- Improved sanitization of HTML attribute values in balanced mode
- Expanded list of dangerous file extensions

### Fixed
- Improved security pattern matching for better threat detection
- Enhanced attribute value sanitization in balanced HTML mode

## [1.0.0] - 2024-01-01

### Added
- Initial release of Laravel Secure Input middleware
- Three security modes: standard, balanced, extreme
- Three actions: sanitize, block, log
- SQL injection protection
- XSS protection
- RCE protection
- Configurable exclusions for routes, methods, and parameters
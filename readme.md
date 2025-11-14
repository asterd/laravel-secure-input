# Laravel Secure Input

Unified, high-performance middleware for Laravel to harden all HTTP input against:

- SQL Injection (even with unsafe string concatenation)
- XSS (script tags, event handlers, dangerous HTML)
- Remote Code Execution patterns
- File Upload Security

It exposes **three security modes** via configuration, using a single middleware class:

- `standard`  → light, backward-compatible
- `balanced`  → strong, XSS-safe HTML whitelist
- `extreme`   → very strict, no HTML, safe chars only

## Installation

### For Laravel 12

```bash
composer require asterd/laravel-secure-input
```

If the package is in your own GitHub namespace, add it as a VCS repository in your main `composer.json`:

```json
{
  "repositories": [
    {
      "type": "vcs",
      "url": "https://github.com/asterd/laravel-secure-input.git"
    }
  ]
}
```

Then run:

```bash
composer require asterd/laravel-secure-input
```

## Publish Config

```bash
php artisan vendor:publish --tag=secure-input-config
```

This will create `config/secure-input.php`.

## Updating Configuration

When updating the package, you may need to update your configuration file to include new features:

1. **Backup your current config**:
   ```bash
   cp config/secure-input.php config/secure-input.backup.php
   ```

2. **Republish the config**:
   ```bash
   php artisan vendor:publish --tag=secure-input-config --force
   ```

3. **Merge your custom settings** from the backup file into the new config file

Alternatively, you can manually add new configuration options by comparing your current config with the default one in the package.

## Usage

### For Laravel 12 (New Structure)

Register the middleware globally in `bootstrap/app.php`:

```php
use SecureInput\Http\Middleware\SecureInput;

->withMiddleware(function (Middleware $middleware) {
    $middleware->append(SecureInput::class);
})
```

Alternatively, you can add it only to specific groups:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->appendToGroup('api', SecureInput::class);
})
```

### For Laravel < 12 (Legacy Structure)

Register the middleware globally in `app/Http/Kernel.php`:

```php
protected $middleware = [
    // ...
    \SecureInput\Http\Middleware\SecureInput::class,
];
```

Alternatively, you can add it only to specific groups (e.g. `api`).

## Configuration

Key options in `config/secure-input.php`:

```php
return [
    'mode'   => env('SECURE_INPUT_MODE', 'standard'), // standard|balanced|extreme
    'action' => env('SECURE_INPUT_ACTION', 'sanitize'), // sanitize|block|log

    'exclude_routes'  => ['debug/*', 'telescope/*'],
    'exclude_methods' => [], // Now processes GET requests by default

    'whitelist_fields' => ['raw_html', 'html_safe', 'description'],
    'exclude_params'   => ['_token', '_method'],

    'log_enabled' => true,
    
    // File upload security
    'file_upload_security' => [
        'enabled' => true,
        'dangerous_extensions' => [
            'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
            'exe', 'bat', 'cmd', 'com', 'scr', 'js', 'vbs',
            'jar', 'asp', 'aspx', 'jsp', 'jspx', 'swf',
            'htaccess', 'htpasswd', 'cgi', 'pl', 'py', 'rb'
        ],
    ],
];
```

### Modes

- **standard**  
  - Detects SQLi, RCE, JS events.
  - Sanitizes by stripping `<script>` and event handlers.
  - Compatible with existing forms / HTML.

- **balanced**  
  - Everything from standard, plus:
  - Allows only a whitelist of HTML tags and attributes.
  - Good trade-off for APIs or admin backoffice.

- **extreme**  
  - No HTML allowed.
  - Allowed characters defined by regex.
  - Ideal for crazy-hostile environments, machine-to-machine APIs, etc.

### Actions

- `sanitize` → cleans input and continues.
- `block` → aborts with 400 on suspicious payload.
- `log` → only logs, does not touch the payload.

### File Upload Security

The middleware now includes file upload security checks that:
- Block dangerous file extensions by default (PHP, executable files, etc.)
- Are configurable through the `file_upload_security` config section
- Can be disabled entirely if not needed
- Log suspicious upload attempts when logging is enabled

## Performance Considerations

The middleware is designed to be lightweight and fast:
- Only processes requests when necessary
- Uses efficient pattern matching for threat detection
- File upload checks only occur when files are actually being uploaded
- Configuration options allow you to disable specific security features for performance-critical routes

## License

MIT
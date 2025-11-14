# Laravel Secure Input

Unified, high-performance middleware for Laravel to harden all HTTP input against:

- SQL Injection (even with unsafe string concatenation)
- XSS (script tags, event handlers, dangerous HTML)
- Remote Code Execution patterns

It exposes **three security modes** via configuration, using a single middleware class:

- `standard`  → light, backward-compatible
- `balanced`  → strong, XSS-safe HTML whitelist
- `extreme`   → very strict, no HTML, safe chars only

## Installation

```bash
composer require asterd/laravel-secure-input
```

If the package is in your own GitHub namespace, add it as a VCS repository in your main `composer.json`:

```json
{
  "repositories": [
    {
      "type": "vcs",
      "url": "https://github.com/<your-user>/laravel-secure-input"
    }
  ]
}
```

Then run:

```bash
composer require dariodurzo/laravel-secure-input
```

## Publish Config

```bash
php artisan vendor:publish --tag=secure-input-config
```

This will create `config/secure-input.php`.

## Usage

Register the middleware globally in `app/Http/Kernel.php`:

```php
protected $middleware = [
    // ...
    \DarioDurzo\SecureInput\Http\Middleware\SecureInput::class,
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
    'exclude_methods' => ['GET'],

    'whitelist_fields' => ['raw_html', 'html_safe', 'description'],
    'exclude_params'   => ['_token', '_method'],

    'log_enabled' => true,
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

## License

MIT
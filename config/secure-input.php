<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Security Level
    |--------------------------------------------------------------------------
    |
    | mode:
    |   - standard : light, backward-compatible hardening
    |   - balanced : strong, good compatibility, XSS-sanitizing HTML whitelist
    |   - extreme  : very strict, no HTML, safe-char whitelist, zero-trust
    |
    */

    'mode' => env('SECURE_INPUT_MODE', 'standard'), // standard | balanced | extreme

    /*
    |--------------------------------------------------------------------------
    | Action on Detection
    |--------------------------------------------------------------------------
    |
    | action:
    |   - sanitize : clean value and continue
    |   - block    : abort(400) on suspicious payload
    |   - log      : only log, do not touch the value
    |
    */

    'action' => env('SECURE_INPUT_ACTION', 'sanitize'), // sanitize | block | log

    /*
    |--------------------------------------------------------------------------
    | Excluded Routes & Methods
    |--------------------------------------------------------------------------
    */

    'exclude_routes' => [
        'debug/*',
        'telescope/*',
        'horizon/*',
    ],

    'exclude_methods' => [
        // 'GET' is now processed for security
    ],

    /*
    |--------------------------------------------------------------------------
    | Field / Param Control
    |--------------------------------------------------------------------------
    */

    'whitelist_fields' => [
        // Fields that should never be sanitized/checked (explicitly trusted)
        'raw_html',
        'html_safe',
        'description',
    ],

    'exclude_params' => [
        '_token',
        '_method',
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */

    'log_enabled' => true,

    /*
    |--------------------------------------------------------------------------
    | File Upload Security
    |--------------------------------------------------------------------------
    |
    | Settings for file upload security checks
    |
    */

    'file_upload_security' => [
        'enabled' => true,
        'dangerous_extensions' => [
            'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
            'exe', 'bat', 'cmd', 'com', 'scr', 'js', 'vbs',
            'jar', 'asp', 'aspx', 'jsp', 'jspx', 'swf',
            'htaccess', 'htpasswd', 'cgi', 'pl', 'py', 'rb'
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Balanced Mode HTML Whitelist
    |--------------------------------------------------------------------------
    */

    'allowed_html_tags' => [
        'b', 'strong', 'i', 'em', 'u',
        'p', 'br', 'ul', 'ol', 'li',
        'span', 'div',
    ],

    'allowed_html_attributes' => [
        'class', 'style',
    ],

    /*
    |--------------------------------------------------------------------------
    | Extreme Mode Character Whitelist
    |--------------------------------------------------------------------------
    |
    | Regex that defines which characters are allowed. Anything else in
    | extreme mode will be considered suspicious, and in sanitize mode
    | will be stripped.
    |
    */

    'extreme_allowed_chars_regex' => '/^[a-zA-Z0-9_\-\s\.,@#\/]+$/',

    // Same characters as above, but inverted, used to strip in extreme+sanitize
    'extreme_strip_forbidden_regex' => '/[^a-zA-Z0-9_\-\s\.,@#\/]/',

];
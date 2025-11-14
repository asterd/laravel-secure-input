<?php

namespace SecureInput\Http\Middleware;

use Closure;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

class SecureInput
{
    /**
     * SQL injection patterns (attempts)
     */
    private array $sqlPatterns = [
        '/\bunion\b/i',
        '/\bselect\b/i',
        '/\binsert\b/i',
        '/\bupdate\b/i',
        '/\bdelete\b/i',
        '/\bdrop\b/i',
        '/\btruncate\b/i',
        '/\bconcat\b/i',
        '/\bsubstring\b/i',
        '/\bascii\b/i',
        '/\bord\b/i',
        '/\bchar\b/i',
        '/--/',
        '/\/\*/',
        '/\*\//',
        '/;(?=\s*|$)/',
        '/\bwaitfor\b/i',
        '/\bdelay\b/i',
        '/\bsleep\b/i',
        '/\bbenchmark\b/i',
    ];

    /**
     * Remote Code Execution / dangerous functions patterns
     */
    private array $rcePatterns = [
        '/\bexec\(/i',
        '/\bsystem\(/i',
        '/\bshell_exec\(/i',
        '/\bpassthru\(/i',
        '/\bproc_open\(/i',
        '/\bpopen\(/i',
        '/\bpcntl_exec\(/i',
        '/`[^`]*`/',  // backtick commands
        '/<\?php/i',
        '/<\?=.*php/i',  // Short tags
        '/base64_decode\(/i',
        '/eval\(/i',
        '/assert\(/i',
        '/file_get_contents\(/i',
        '/file_put_contents\(/i',
        '/fopen\(/i',
        '/fwrite\(/i',
        '/curl_exec\(/i',
    ];

    public function handle($request, Closure $next)
    {
        $cfg = config('secure-input', []);

        $mode   = $cfg['mode']   ?? 'standard';
        $action = $cfg['action'] ?? 'sanitize';

        // Exclude routes
        foreach ($cfg['exclude_routes'] ?? [] as $pattern) {
            if (Str::is($pattern, $request->path())) {
                return $next($request);
            }
        }

        // Exclude methods
        if (in_array($request->method(), $cfg['exclude_methods'] ?? [], true)) {
            return $next($request);
        }

        // Check file uploads for security issues
        $this->checkFileUploads($request, $cfg, $mode, $action);

        $input = $request->all();
        $clean = $this->processArray($input, $cfg, $mode, $action);

        $request->merge($clean);

        return $next($request);
    }

    private function checkFileUploads($request, array $cfg, string $mode, string $action): void
    {
        // Check if file upload security is enabled
        $fileSecurityCfg = $cfg['file_upload_security'] ?? [];
        if (!($fileSecurityCfg['enabled'] ?? true)) {
            return;
        }

        if (!$request->files->count()) {
            return;
        }

        // Get dangerous extensions from config or use default
        $dangerousExtensions = $fileSecurityCfg['dangerous_extensions'] ?? [
            'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
            'exe', 'bat', 'cmd', 'com', 'scr', 'js', 'vbs',
            'jar', 'asp', 'aspx', 'jsp', 'jspx', 'swf',
            'htaccess', 'htpasswd', 'cgi', 'pl', 'py', 'rb'
        ];

        foreach ($request->files as $key => $file) {
            if (empty($file)) {
                continue;
            }

            // Handle multiple file uploads
            $files = is_array($file) ? $file : [$file];
            
            foreach ($files as $uploadedFile) {
                if (!$uploadedFile || !$uploadedFile->isValid()) {
                    continue;
                }

                // Check file extension
                $extension = strtolower($uploadedFile->getClientOriginalExtension());
                
                if (in_array($extension, $dangerousExtensions)) {
                    $threatInfo = [
                        'key' => $key,
                        'filename' => $uploadedFile->getClientOriginalName(),
                        'extension' => $extension,
                        'mode' => $mode,
                        'action' => $action,
                    ];

                    if ($cfg['log_enabled'] ?? true) {
                        Log::warning('SECURE_INPUT: dangerous file upload attempt detected', $threatInfo);
                    }

                    if ($action === 'block') {
                        abort(400, 'Dangerous file upload blocked');
                    }
                    
                    // For sanitize action, we could rename or reject the file
                    // but for now we'll just log and continue
                }

                // Additional file content checks could be added here for performance-sensitive environments
                // For example: checking MIME type, file size limits, etc.
            }
        }
    }

    private function processArray(array $input, array $cfg, string $mode, string $action): array
    {
        foreach ($input as $key => $value) {

            if (in_array($key, $cfg['exclude_params'] ?? [], true)) {
                continue;
            }

            if (is_array($value)) {
                $input[$key] = $this->processArray($value, $cfg, $mode, $action);
                continue;
            }

            if (!is_string($value)) {
                continue;
            }

            if (in_array($key, $cfg['whitelist_fields'] ?? [], true)) {
                continue;
            }

            $isThreat = $this->detectThreat($value, $mode, $cfg);

            if ($isThreat && ($cfg['log_enabled'] ?? true)) {
                Log::warning('SECURE_INPUT: threat detected', [
                    'key'   => $key,
                    'value' => $value,
                    'mode'  => $mode,
                    'action'=> $action,
                ]);
            }

            if ($isThreat && $action === 'block') {
                abort(400, 'Suspicious input blocked');
            }

            if ($action === 'sanitize') {
                $value = $this->sanitizeValue($value, $mode, $cfg);
            }

            $input[$key] = $value;
        }

        return $input;
    }

    private function detectThreat(string $value, string $mode, array $cfg): bool
    {
        // Base SQL + RCE checks
        foreach (array_merge($this->sqlPatterns, $this->rcePatterns) as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        // HTML event handlers (e.g. onclick, onload)
        if (preg_match('/on\w+="[^"]*"/i', $value)) {
            return true;
        }

        // Additional XSS patterns
        if (preg_match('/javascript:/i', $value)) {
            return true;
        }

        if (preg_match('/vbscript:/i', $value)) {
            return true;
        }

        if (preg_match('/data:text\/html/i', $value)) {
            return true;
        }

        // Extreme mode: character whitelist enforcement
        if ($mode === 'extreme') {
            $allowedRegex = $cfg['extreme_allowed_chars_regex'] ?? '/^[a-zA-Z0-9_\-\s\.,@#\/]+$/';
            if (!preg_match($allowedRegex, $value)) {
                return true;
            }
        }

        return false;
    }

    private function sanitizeValue(string $value, string $mode, array $cfg): string
    {
        // Remove <script> blocks and JS event handlers in any mode
        $value = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $value);
        $value = preg_replace('/on\w+="[^"]*"/i', '', $value);
        $value = preg_replace('/javascript:/i', '', $value);
        $value = preg_replace('/vbscript:/i', '', $value);

        if ($mode === 'balanced') {
            $value = $this->sanitizeBalancedHtml($value, $cfg);
        }

        if ($mode === 'extreme') {
            $value = $this->sanitizeExtreme($value, $cfg);
        }

        // Standard mode: or final pass in other modes
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8', false);
    }

    private function sanitizeBalancedHtml(string $value, array $cfg): string
    {
        $allowedTags  = $cfg['allowed_html_tags'] ?? [];
        $allowedAttrs = $cfg['allowed_html_attributes'] ?? [];

        if (!empty($allowedTags)) {
            $tagWhitelist = '<' . implode('><', $allowedTags) . '>';
            $value = strip_tags($value, $tagWhitelist);
        } else {
            // No tags allowed if whitelist empty
            $value = strip_tags($value);
        }

        // Clean attributes by whitelist
        if (!empty($allowedAttrs)) {
            $value = preg_replace_callback(
                '/<([a-z0-9]+)([^>]*)>/i',
                function ($matches) use ($allowedAttrs) {
                    $tag   = $matches[1];
                    $attrs = $matches[2];

                    $cleanAttrs = '';
                    if (preg_match_all('/([a-z\-]+)="([^"]*)"/i', $attrs, $found)) {
                        foreach ($found[1] as $i => $attrName) {
                            if (in_array($attrName, $allowedAttrs, true)) {
                                $attrValue = $found[2][$i];
                                // Sanitize attribute values
                                $attrValue = htmlspecialchars($attrValue, ENT_QUOTES, 'UTF-8');
                                $cleanAttrs .= ' ' . $attrName . '="' . $attrValue . '"';
                            }
                        }
                    }

                    return '<' . $tag . $cleanAttrs . '>';
                },
                $value
            );
        } else {
            // Strip all attributes if none allowed
            $value = preg_replace('/<([a-z0-9]+)[^>]*>/i', '<$1>', $value);
        }

        return $value;
    }

    private function sanitizeExtreme(string $value, array $cfg): string
    {
        // No HTML in extreme mode
        $value = strip_tags($value);

        // Strip any forbidden characters
        $stripForbidden = $cfg['extreme_strip_forbidden_regex'] ?? '/[^a-zA-Z0-9_\-\s\.,@#\/]/';
        $value = preg_replace($stripForbidden, '', $value);

        return $value;
    }
}
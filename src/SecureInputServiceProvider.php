<?php

namespace SecureInput;

use Illuminate\Support\ServiceProvider;

class SecureInputServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/secure-input.php' => $this->app->configPath('secure-input.php'),
        ], 'secure-input-config');
    }

    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/secure-input.php',
            'secure-input'
        );
    }
}

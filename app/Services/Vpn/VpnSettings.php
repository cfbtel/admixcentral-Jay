<?php

namespace App\Services\Vpn;

use App\Models\SystemSetting;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;

/**
 * VPN module settings, kept in system_settings (keys "vpn_*") so they're set on a settings page,
 * not in the server's .env. The Microsoft client secret is encrypted with the app key.
 */
class VpnSettings
{
    private const KEYS = ['ms_client_id', 'ms_client_secret', 'portal_host', 'max_devices', 'proxy_ips'];

    public static function get(string $key, ?string $default = null): ?string
    {
        $value = Cache::remember("vpn_setting:{$key}", 60, fn () => SystemSetting::where('key', "vpn_{$key}")->value('value') ?? '');
        return $value === '' ? $default : $value;
    }

    public static function set(string $key, ?string $value): void
    {
        if (!in_array($key, self::KEYS, true)) {
            throw new \InvalidArgumentException("Unknown VPN setting {$key}");
        }
        if ($key === 'ms_client_secret' && $value !== null && $value !== '') {
            $value = Crypt::encryptString($value);
        }
        SystemSetting::updateOrCreate(['key' => "vpn_{$key}"], ['value' => $value ?? '']);
        Cache::forget("vpn_setting:{$key}");
    }

    public static function clientId(): ?string
    {
        return self::get('ms_client_id');
    }

    public static function clientSecret(): ?string
    {
        $sealed = self::get('ms_client_secret');
        if (!$sealed) {
            return null;
        }
        try {
            return Crypt::decryptString($sealed);
        } catch (\Throwable) {
            return null; // app key changed: the secret has to be entered again
        }
    }

    public static function hasClientSecret(): bool
    {
        return self::clientSecret() !== null;
    }

    /** Public host name of the staff page, e.g. wguard.cfbtel.com (no scheme, no path). */
    public static function portalHost(): ?string
    {
        return self::get('portal_host', env('VPN_PORTAL_HOST'));
    }

    public static function portalUrl(string $path = '/vpn'): string
    {
        $host = self::portalHost();
        return $host ? 'https://' . $host . $path : rtrim(config('app.url'), '/') . $path;
    }

    public static function maxDevices(): int
    {
        return max(1, min(50, (int) self::get('max_devices', '5')));
    }

    /** Reverse proxies in front of the staff VPN page whose X-Forwarded-For may be trusted. */
    public static function proxyIps(): array
    {
        return array_values(array_filter(array_map('trim', explode(',', (string) self::get('proxy_ips', ''))), fn ($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
    }

    public static function microsoftReady(): bool
    {
        return self::clientId() && self::hasClientSecret();
    }
}

<?php

namespace App\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Release notes for the "What's new" window, read from CHANGELOG.md sections headed
 * "### Added — v0.12.0", "### Fixed — v0.12.0" and so on.
 */
class ReleaseNotes
{
    public static function currentVersion(): string
    {
        $file = base_path('VERSION');

        return is_readable($file) ? trim((string) file_get_contents($file)) : 'v0.0.0';
    }

    /** @return array<string, array<int, array{type: string, markdown: string}>> newest first, keyed by version (v0.12.0) */
    public static function all(): array
    {
        $file = base_path('CHANGELOG.md');
        if (!is_readable($file)) {
            return [];
        }

        return Cache::remember('release_notes:' . md5_file($file), now()->addDay(), function () use ($file) {
            $versions = [];
            $current = null;
            foreach (preg_split('/\R/', (string) file_get_contents($file)) as $line) {
                if (preg_match('/^###\s+(\w+)\s+[—-]+\s+(v\d+\.\d+\.\d+)\s*$/u', $line, $m)) {
                    $current = ['version' => $m[2], 'type' => $m[1]];
                    $versions[$m[2]][] = ['type' => $m[1], 'markdown' => ''];
                    continue;
                }
                if (str_starts_with($line, '## ') || str_starts_with($line, '### ')) {
                    $current = null;
                    continue;
                }
                if ($current) {
                    $i = array_key_last($versions[$current['version']]);
                    $versions[$current['version']][$i]['markdown'] .= $line . "\n";
                }
            }
            uksort($versions, fn ($a, $b) => version_compare(ltrim($b, 'v'), ltrim($a, 'v')));

            return $versions;
        });
    }

    /** @return array<int, array{type: string, html: string}> */
    public static function for(string $version): array
    {
        return array_map(fn ($s) => [
            'type' => $s['type'],
            'html' => Str::markdown(trim($s['markdown']), ['html_input' => 'strip', 'allow_unsafe_links' => false]),
        ], self::all()[$version] ?? []);
    }

    public static function unseenBy(?\App\Models\User $user): bool
    {
        if (!$user) {
            return false;
        }
        $version = self::currentVersion();

        return $user->whats_new_seen !== $version && self::for($version) !== [];
    }
}

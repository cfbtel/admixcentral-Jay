<?php

namespace App\Services\Deploy;

/**
 * The changes a deployment sends: cleans up what the form sent, checks what can be checked without a
 * firewall, and names each change for the pages. Firewall-specific checks (interfaces, aliases, packages)
 * are done on each firewall by the helper.
 */
final class DeployItems
{
    public const KINDS = [
        'rule' => 'Firewall rule',
        'alias' => 'Alias',
        'nat' => 'Port forward',
        'pfb_ipv4' => 'pfBlockerNG IP list',
    ];

    public const MAX_ITEMS = 50;

    /** Packages each kind needs on the firewall. */
    public const PACKAGES = ['pfb_ipv4' => 'pfBlockerNG'];

    /**
     * @return array{0: array, 1: array<int, string>} [clean items, errors]
     */
    public static function normalize(array $input): array
    {
        $items = [];
        $errors = [];
        foreach (array_values($input) as $n => $raw) {
            if (!is_array($raw)) {
                continue;
            }
            $no = $n + 1;
            $kind = (string) ($raw['kind'] ?? '');
            $s = fn (string $k, int $max = 250) => mb_substr(trim((string) ($raw[$k] ?? '')), 0, $max);
            switch ($kind) {
                case 'alias':
                    $entries = $raw['entries'] ?? [];
                    if (is_string($entries)) {
                        $entries = preg_split('/[\s,]+/', $entries);
                    }
                    $entries = array_values(array_unique(array_filter(array_map(fn ($e) => mb_substr(trim((string) $e), 0, 500), (array) $entries), 'strlen')));
                    $item = ['kind' => 'alias', 'name' => $s('name', 31), 'type' => in_array($raw['type'] ?? '', ['host', 'network', 'port', 'url', 'urltable'], true) ? $raw['type'] : 'host',
                        'entries' => array_slice($entries, 0, 5000), 'descr' => $s('descr'), 'updatefreq' => max(1, min(365, (int) ($raw['updatefreq'] ?? 1)))];
                    if (!preg_match('/^[A-Za-z0-9_]{1,31}$/', $item['name'])) {
                        $errors[] = "Change {$no}: the alias name can use up to 31 letters, numbers and underscores.";
                    }
                    if (!$item['entries']) {
                        $errors[] = "Change {$no}: the alias needs at least one entry.";
                    }
                    break;

                case 'rule':
                    $item = ['kind' => 'rule', 'interface' => $s('interface', 40) ?: 'WAN', 'action' => in_array($raw['action'] ?? '', ['pass', 'block', 'reject'], true) ? $raw['action'] : 'pass',
                        'ipprotocol' => in_array($raw['ipprotocol'] ?? '', ['inet', 'inet6', 'inet46'], true) ? $raw['ipprotocol'] : 'inet',
                        'protocol' => in_array($raw['protocol'] ?? '', ['any', 'tcp', 'udp', 'tcp/udp', 'icmp'], true) ? $raw['protocol'] : 'any',
                        'source' => $s('source', 120) ?: 'any', 'source_port' => $s('source_port', 40), 'destination' => $s('destination', 120) ?: 'any',
                        'destination_port' => $s('destination_port', 40), 'descr' => $s('descr', 200),
                        'placement' => ($raw['placement'] ?? 'top') === 'bottom' ? 'bottom' : 'top', 'log' => filter_var($raw['log'] ?? false, FILTER_VALIDATE_BOOLEAN)];
                    if ($item['descr'] === '') {
                        $errors[] = "Change {$no}: every rule needs a description. PFCentral uses it to find the rule again.";
                    }
                    break;

                case 'nat':
                    $item = ['kind' => 'nat', 'interface' => $s('interface', 40) ?: 'WAN', 'protocol' => in_array($raw['protocol'] ?? '', ['tcp', 'udp', 'tcp/udp'], true) ? $raw['protocol'] : 'tcp',
                        'source' => $s('source', 120) ?: 'any', 'destination' => $s('destination', 120), 'destination_port' => $s('destination_port', 40),
                        'target' => $s('target', 60), 'local_port' => $s('local_port', 20), 'descr' => $s('descr', 200)];
                    if ($item['descr'] === '') {
                        $errors[] = "Change {$no}: every port forward needs a description. PFCentral uses it to find it again.";
                    }
                    if ($item['destination_port'] === '') {
                        $errors[] = "Change {$no}: the port forward needs an outside port.";
                    }
                    if ($item['target'] === '') {
                        $errors[] = "Change {$no}: the port forward needs an internal address.";
                    }
                    break;

                case 'pfb_ipv4':
                    $rows = [];
                    foreach (array_slice((array) ($raw['rows'] ?? []), 0, 50) as $row) {
                        $url = mb_substr(trim((string) ($row['url'] ?? '')), 0, 1000);
                        $header = mb_substr(trim((string) ($row['header'] ?? '')), 0, 60);
                        if ($url === '' && $header === '') {
                            continue;
                        }
                        $rows[] = ['format' => in_array($row['format'] ?? '', ['auto', 'geoip', 'regex', 'whois', 'asn', 'rsync'], true) ? $row['format'] : 'auto',
                            'state' => in_array($row['state'] ?? '', ['Enabled', 'Disabled', 'Hold', 'Flex'], true) ? $row['state'] : 'Enabled', 'url' => $url, 'header' => $header];
                    }
                    $item = ['kind' => 'pfb_ipv4', 'name' => $s('name', 24), 'descr' => $s('descr'), 'rows' => $rows,
                        'action' => (string) ($raw['action'] ?? 'Deny_Inbound'), 'cron' => (string) ($raw['cron'] ?? 'Never'), 'dow' => (string) ($raw['dow'] ?? '1'),
                        'aliaslog' => ($raw['aliaslog'] ?? 'enabled') === 'disabled' ? 'disabled' : 'enabled', 'custom' => mb_substr((string) ($raw['custom'] ?? ''), 0, 100000)];
                    if (!preg_match('/^[A-Za-z0-9_]{1,24}$/', $item['name'])) {
                        $errors[] = "Change {$no}: the pfBlockerNG list name can use up to 24 letters, numbers and underscores.";
                    }
                    if (!$rows && trim($item['custom']) === '') {
                        $errors[] = "Change {$no}: the pfBlockerNG list needs at least one source or some custom entries.";
                    }
                    foreach ($rows as $r => $row) {
                        if ($row['url'] === '' || !preg_match('/^[A-Za-z0-9_]+$/', $row['header'])) {
                            $errors[] = "Change {$no}, source " . ($r + 1) . ': both the source and a header (letters, numbers, underscores) are needed.';
                        }
                    }
                    break;

                default:
                    $errors[] = "Change {$no}: unknown kind of change.";
                    continue 2;
            }
            $item['label'] = self::label($item);
            $items[] = $item;
        }
        if (!$items) {
            $errors[] = 'Add at least one change.';
        }
        if (count($items) > self::MAX_ITEMS) {
            $errors[] = 'A deployment can have at most ' . self::MAX_ITEMS . ' changes.';
        }
        return [$items, array_values(array_unique($errors))];
    }

    public static function label(array $item): string
    {
        return match ($item['kind']) {
            'alias' => "Alias {$item['name']} ({$item['type']}, " . count($item['entries']) . ' ' . (count($item['entries']) === 1 ? 'entry' : 'entries') . ')',
            'rule' => ucfirst($item['action']) . " rule on {$item['interface']}: {$item['descr']}",
            'nat' => "Port forward on {$item['interface']} {$item['destination_port']} → {$item['target']}" . ($item['local_port'] !== '' ? ":{$item['local_port']}" : '') . ": {$item['descr']}",
            'pfb_ipv4' => "pfBlockerNG IP list {$item['name']} (" . str_replace('_', ' ', $item['action']) . ')',
            default => 'Change',
        };
    }

    /** Packages the deployment needs, for the pre-check summary. */
    public static function packages(array $items): array
    {
        $need = [];
        foreach ($items as $i) {
            if (isset(self::PACKAGES[$i['kind'] ?? ''])) {
                $need[self::PACKAGES[$i['kind']]] = true;
            }
        }
        return array_keys($need);
    }
}

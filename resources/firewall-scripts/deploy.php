<?php
/*
 * PFCentral deployment helper.
 *
 * PFCentral copies this file to the firewall (/root/.admixcentral/) through the pfSense REST API
 * command prompt and runs it with pfSense's own PHP:
 *
 *   /usr/local/bin/php deploy-<hash>.php <check|apply|undo> [<base64 JSON> | @/tmp/acx_<name>]
 *
 * It reads and writes the same config.xml sections the pfSense pages use, so everything it adds
 * is visible and editable in the pfSense web interface. The answer is one line: "ACXDP:" and
 * base64 encoded JSON.
 *
 * Kinds of change ("items"):
 *   alias      { name, type, entries[], descr }
 *   rule       { interface, action, ipprotocol, protocol, source, source_port, destination, destination_port, descr, placement, log }
 *   nat        { interface, protocol, destination, destination_port, target, local_port, source, descr }   (with its linked pass rule)
 *   pfb_ipv4   { name, descr, rows[{format,state,url,header}], action, cron, dow, aliaslog, custom }        (pfBlockerNG)
 *
 * apply: checks everything first and changes nothing if any item has a problem. All items are written
 * in one configuration save. If the firewall can't load the new rules, the previous settings are put
 * back and the answer says so. The answer carries what is needed to undo the deployment later.
 */

error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '0');

const ACX_MARK = 'ACXDP:';
const ACX_PFB_INC = '/usr/local/pkg/pfblockerng/pfblockerng.inc';
const ACX_TAG = 'PFCentral';

function acx_out(array $data): void
{
    $json = json_encode($data, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
    echo "\n" . ACX_MARK . base64_encode((string) $json) . "\n";
    exit(0);
}

function acx_fail(string $message, array $extra = []): void
{
    acx_out(['ok' => false, 'error' => $message] + $extra);
}

$action = $argv[1] ?? 'check';
$raw = $argv[2] ?? '';
if ($raw !== '' && $raw[0] === '@') {
    $path = substr($raw, 1);
    if (!preg_match('#^/tmp/acx_[A-Za-z0-9_]+$#', $path)) {
        acx_fail('Invalid argument file.');
    }
    $raw = trim((string) @file_get_contents($path));
    @unlink($path);
}
$args = $raw === '' ? [] : json_decode((string) base64_decode($raw), true);
if (!is_array($args)) {
    $args = [];
}

require_once('globals.inc');
require_once('config.inc');
require_once('functions.inc');
require_once('util.inc');
require_once('filter.inc');
require_once('pkg-utils.inc');

if (!function_exists('config_get_path')) {
    acx_fail('This pfSense version is too old. pfSense 2.7 or newer is needed.');
}

/* ------------------------------------------------------------------ facts */

function acx_pfb(): array
{
    foreach (config_get_path('installedpackages/package', []) as $pkg) {
        if (is_array($pkg) && stripos($pkg['name'] ?? '', 'pfblockerng') !== false) {
            $installed = file_exists(ACX_PFB_INC);
            $version = (string) ($pkg['version'] ?? '');
            // pfBlockerNG 3.x (and -devel) use the configuration layout this helper writes.
            $compatible = $installed && version_compare(preg_replace('/[^0-9.].*$/', '', $version), '3.0', '>=');
            return ['installed' => $installed, 'name' => (string) $pkg['name'], 'version' => $version, 'compatible' => $compatible];
        }
    }
    return ['installed' => false, 'name' => '', 'version' => '', 'compatible' => false];
}

function acx_interfaces(): array
{
    $out = [];
    foreach (config_get_path('interfaces', []) as $key => $if) {
        if (is_array($if)) {
            $out[$key] = ['key' => $key, 'descr' => (string) ($if['descr'] ?? strtoupper($key)), 'enabled' => isset($if['enable']) || $key === 'wan' || $key === 'lan'];
        }
    }
    return $out;
}

function acx_interface(string $name): ?string
{
    $name = trim($name);
    if ($name === '') {
        return null;
    }
    foreach (acx_interfaces() as $key => $if) {
        if (strcasecmp($key, $name) === 0 || strcasecmp($if['descr'], $name) === 0) {
            return $key;
        }
    }
    return null;
}

function acx_version(): string
{
    return trim((string) @file_get_contents('/etc/version'));
}

/* ------------------------------------------------------- address helpers */

const ACX_SPECIAL = ['any', 'self', '(self)', 'wanip', 'lanip', 'wan', 'lan'];

function acx_alias_names(array $items): array
{
    $names = [];
    foreach (config_get_path('aliases/alias', []) as $a) {
        if (is_array($a) && isset($a['name'])) {
            $names[strtolower($a['name'])] = true;
        }
    }
    foreach (config_get_path('installedpackages/pfblockernglistsv4/config', []) as $g) {
        if (is_array($g) && isset($g['aliasname'])) {
            $names[strtolower('pfB_' . $g['aliasname'])] = true;
        }
    }
    foreach ($items as $it) {
        if (($it['kind'] ?? '') === 'alias') {
            $names[strtolower((string) $it['name'])] = true;
        } elseif (($it['kind'] ?? '') === 'pfb_ipv4') {
            $names[strtolower('pfB_' . $it['name'])] = true;
        }
    }
    return $names;
}

/**
 * "any", "self", "wanip", "lanip", "wannet" / "<interface>net", an IP, a network (CIDR) or an alias name.
 * Returns the pfSense config form, or an error string.
 */
function acx_address(string $value, array $aliases, string $port = '')
{
    $value = trim($value);
    $not = false;
    if ($value !== '' && $value[0] === '!') {
        $not = true;
        $value = trim(substr($value, 1));
    }
    $lower = strtolower($value);
    $out = [];
    if ($value === '' || $lower === 'any') {
        $out['any'] = '';
    } elseif ($lower === 'self' || $lower === '(self)' || $lower === 'this firewall') {
        $out['network'] = '(self)';
    } elseif (preg_match('/^([a-z0-9_]+)(ip|net)$/i', $value, $m) && acx_interface($m[1]) !== null) {
        $out['network'] = acx_interface($m[1]) . strtolower($m[2]);
    } elseif (is_ipaddr($value) || is_subnet($value)) {
        $out['address'] = $value;
    } elseif (preg_match('/^[A-Za-z0-9_]+$/', $value)) {
        if (!isset($aliases[$lower])) {
            return "There is no alias named {$value} on this firewall or in this deployment.";
        }
        $out['address'] = $value;
    } else {
        return "\"{$value}\" isn't an address, network or alias name.";
    }
    if ($not) {
        $out['not'] = '';
    }
    if ($port !== '') {
        $out['port'] = $port;
    }
    return $out;
}

function acx_port(string $value, array $aliases)
{
    $value = trim(str_replace(' ', '', $value));
    if ($value === '') {
        return '';
    }
    if (preg_match('/^\d{1,5}([-:]\d{1,5})?$/', $value)) {
        $value = str_replace('-', ':', $value);
        foreach (explode(':', $value) as $p) {
            if ((int) $p < 1 || (int) $p > 65535) {
                return "Port {$p} is out of range.";
            }
        }
        return $value;
    }
    if (preg_match('/^[A-Za-z0-9_]+$/', $value) && isset($aliases[strtolower($value)])) {
        return $value;
    }
    return "\"{$value}\" isn't a port, port range or port alias.";
}

/* -------------------------------------------------- build config entries */

function acx_created(): array
{
    return ['time' => time(), 'username' => ACX_TAG . ' deployment'];
}

/** @return array{0: ?array, 1: array} [config entry or null, errors] */
function acx_build(array $it, array $aliases): array
{
    $e = [];
    $kind = $it['kind'] ?? '';
    switch ($kind) {
        case 'alias':
            $name = trim((string) ($it['name'] ?? ''));
            if (!preg_match('/^[A-Za-z0-9_]{1,31}$/', $name)) {
                $e[] = 'The alias name can use up to 31 letters, numbers and underscores.';
            }
            $type = (string) ($it['type'] ?? 'host');
            if (!in_array($type, ['host', 'network', 'port', 'url', 'urltable', 'url_ports', 'urltable_ports'], true)) {
                $e[] = "Unknown alias type {$type}.";
            }
            $entries = array_values(array_filter(array_map('trim', (array) ($it['entries'] ?? [])), 'strlen'));
            if (!$entries) {
                $e[] = "Alias {$name} needs at least one entry.";
            }
            foreach ($entries as $x) {
                $ok = match ($type) {
                    'host' => is_ipaddr($x) || is_hostname($x) || is_iprange($x) || isset($aliases[strtolower($x)]),
                    'network' => is_subnet($x) || is_ipaddr($x) || is_hostname($x) || isset($aliases[strtolower($x)]),
                    'port' => (bool) preg_match('/^\d{1,5}(:\d{1,5})?$/', $x) || isset($aliases[strtolower($x)]),
                    default => (bool) preg_match('#^https?://\S+$#i', $x),
                };
                if (!$ok) {
                    $e[] = "Alias {$name}: \"{$x}\" doesn't fit a {$type} alias.";
                }
            }
            $entry = ['name' => $name, 'type' => $type, 'descr' => (string) ($it['descr'] ?? ''), 'detail' => implode('||', array_fill(0, count($entries), ACX_TAG))];
            if (in_array($type, ['url', 'url_ports'], true)) {
                $entry['url'] = $entries[0];
                $entry['aliasurl'] = $entries;
                $entry['address'] = '';
            } elseif (in_array($type, ['urltable', 'urltable_ports'], true)) {
                $entry['url'] = $entries[0];
                $entry['updatefreq'] = (string) max(1, (int) ($it['updatefreq'] ?? 1));
                $entry['address'] = '';
            } else {
                $entry['address'] = implode(' ', $entries);
            }
            return [$e ? null : $entry, $e];

        case 'rule':
            $descr = trim((string) ($it['descr'] ?? ''));
            if ($descr === '') {
                $e[] = 'Every rule needs a description: it is how PFCentral finds the rule again.';
            }
            $if = acx_interface((string) ($it['interface'] ?? ''));
            if ($if === null) {
                $e[] = "Interface \"{$it['interface']}\" isn't on this firewall.";
            }
            $type = in_array($it['action'] ?? 'pass', ['pass', 'block', 'reject'], true) ? $it['action'] : 'pass';
            $ipp = in_array($it['ipprotocol'] ?? 'inet', ['inet', 'inet6', 'inet46'], true) ? ($it['ipprotocol'] ?? 'inet') : 'inet';
            $proto = in_array($it['protocol'] ?? 'any', ['any', 'tcp', 'udp', 'tcp/udp', 'icmp'], true) ? ($it['protocol'] ?? 'any') : 'any';
            $ports = in_array($proto, ['tcp', 'udp', 'tcp/udp'], true);
            $sp = $ports ? acx_port((string) ($it['source_port'] ?? ''), $aliases) : '';
            $dp = $ports ? acx_port((string) ($it['destination_port'] ?? ''), $aliases) : '';
            foreach ([$sp, $dp] as $p) {
                if (is_string($p) && $p !== '' && str_contains($p, ' ')) {
                    $e[] = $p;
                }
            }
            $src = acx_address((string) ($it['source'] ?? 'any'), $aliases, is_string($sp) && !str_contains($sp, ' ') ? $sp : '');
            $dst = acx_address((string) ($it['destination'] ?? 'any'), $aliases, is_string($dp) && !str_contains($dp, ' ') ? $dp : '');
            foreach ([$src, $dst] as $a) {
                if (is_string($a)) {
                    $e[] = $a;
                }
            }
            if ($e) {
                return [null, $e];
            }
            $rule = ['type' => $type, 'interface' => $if, 'ipprotocol' => $ipp, 'source' => $src, 'destination' => $dst, 'descr' => $descr];
            if ($proto !== 'any') {
                $rule['protocol'] = $proto;
            }
            if (!empty($it['log'])) {
                $rule['log'] = '';
            }
            return [$rule, []];

        case 'nat':
            $descr = trim((string) ($it['descr'] ?? ''));
            if ($descr === '') {
                $e[] = 'Every port forward needs a description: it is how PFCentral finds it again.';
            }
            $if = acx_interface((string) ($it['interface'] ?? 'wan'));
            if ($if === null) {
                $e[] = "Interface \"{$it['interface']}\" isn't on this firewall.";
            }
            $proto = in_array($it['protocol'] ?? 'tcp', ['tcp', 'udp', 'tcp/udp'], true) ? ($it['protocol'] ?? 'tcp') : 'tcp';
            $dport = acx_port((string) ($it['destination_port'] ?? ''), $aliases);
            $lport = acx_port((string) ($it['local_port'] ?? ''), $aliases);
            if ($dport === '') {
                $e[] = 'The port forward needs an outside port.';
            } elseif (str_contains($dport, ' ')) {
                $e[] = $dport;
            }
            if ($lport === '') {
                $lport = is_string($dport) ? explode(':', $dport)[0] : '';
            } elseif (str_contains($lport, ' ')) {
                $e[] = $lport;
            } else {
                $lport = explode(':', $lport)[0];
            }
            $target = trim((string) ($it['target'] ?? ''));
            if (!is_ipaddr($target) && !(preg_match('/^[A-Za-z0-9_]+$/', $target) && isset($aliases[strtolower($target)]))) {
                $e[] = "The internal address \"{$target}\" isn't an IP address or alias.";
            }
            $dest = trim((string) ($it['destination'] ?? '')) ?: ($if ? $if . 'ip' : 'wanip');
            $dst = acx_address($dest, $aliases, is_string($dport) ? $dport : '');
            $src = acx_address((string) ($it['source'] ?? 'any'), $aliases);
            foreach ([$src, $dst] as $a) {
                if (is_string($a)) {
                    $e[] = $a;
                }
            }
            if ($e) {
                return [null, $e];
            }
            $nat = ['interface' => $if, 'ipprotocol' => 'inet', 'protocol' => $proto, 'source' => $src, 'destination' => $dst,
                'target' => $target, 'local-port' => $lport, 'descr' => $descr];
            return [$nat, []];

        case 'pfb_ipv4':
            $name = trim((string) ($it['name'] ?? ''));
            if (!preg_match('/^[A-Za-z0-9_]{1,24}$/', $name)) {
                $e[] = 'The pfBlockerNG list name can use up to 24 letters, numbers and underscores.';
            }
            $rows = [];
            foreach ((array) ($it['rows'] ?? []) as $n => $row) {
                $url = trim((string) ($row['url'] ?? ''));
                $header = trim((string) ($row['header'] ?? ''));
                if ($url === '' && $header === '') {
                    continue;
                }
                if ($url === '' || !preg_match('/^[A-Za-z0-9_]+$/', $header)) {
                    $e[] = 'Source line ' . ($n + 1) . ': both the source and a header (letters, numbers, underscores) are needed.';
                }
                $format = in_array($row['format'] ?? 'auto', ['auto', 'geoip', 'regex', 'whois', 'asn', 'rsync'], true) ? $row['format'] : 'auto';
                $state = in_array($row['state'] ?? 'Enabled', ['Enabled', 'Disabled', 'Hold', 'Flex'], true) ? $row['state'] : 'Enabled';
                $rows[] = ['format' => $format, 'state' => $state, 'url' => $url, 'header' => $header];
            }
            $custom = trim(str_replace("\r", '', (string) ($it['custom'] ?? '')));
            if (!$rows && $custom === '') {
                $e[] = 'The pfBlockerNG list needs at least one source or some custom entries.';
            }
            $actions = ['Disabled', 'Deny_Inbound', 'Deny_Outbound', 'Deny_Both', 'Permit_Inbound', 'Permit_Outbound', 'Permit_Both',
                'Match_Inbound', 'Match_Outbound', 'Match_Both', 'Alias_Deny', 'Alias_Permit', 'Alias_Match', 'Alias_Native'];
            $crons = ['Never', '01hour', '02hours', '03hours', '04hours', '06hours', '08hours', '12hours', 'EveryDay', 'Weekly'];
            if ($e) {
                return [null, $e];
            }
            $g = [
                'aliasname' => $name,
                'description' => substr(trim((string) ($it['descr'] ?? '')), 0, 250),
                'row' => $rows,
                'custom' => $custom === '' ? '' : base64_encode($custom),
                'action' => in_array($it['action'] ?? '', $actions, true) ? $it['action'] : 'Deny_Inbound',
                'cron' => in_array($it['cron'] ?? '', $crons, true) ? $it['cron'] : 'Never',
                'dow' => in_array((string) ($it['dow'] ?? '1'), ['1', '2', '3', '4', '5', '6', '7'], true) ? (string) $it['dow'] : '1',
                'aliaslog' => ($it['aliaslog'] ?? 'enabled') === 'disabled' ? 'disabled' : 'enabled',
            ];
            return [$g, []];
    }
    return [null, ["Unknown kind of change \"{$kind}\"."]];
}

/* ------------------------------------------------------ find what exists */

function acx_find(string $kind, array $entry): ?int
{
    switch ($kind) {
        case 'alias':
            foreach (config_get_path('aliases/alias', []) as $i => $a) {
                if (is_array($a) && strcasecmp($a['name'] ?? '', $entry['name']) === 0) {
                    return $i;
                }
            }
            return null;
        case 'rule':
            foreach (config_get_path('filter/rule', []) as $i => $r) {
                if (is_array($r) && empty($r['associated-rule-id']) && empty($r['floating']) && ($r['interface'] ?? '') === $entry['interface'] && ($r['descr'] ?? '') === $entry['descr']) {
                    return $i;
                }
            }
            return null;
        case 'nat':
            foreach (config_get_path('nat/rule', []) as $i => $r) {
                if (is_array($r) && ($r['interface'] ?? '') === $entry['interface'] && ($r['descr'] ?? '') === $entry['descr']) {
                    return $i;
                }
            }
            return null;
        case 'pfb_ipv4':
            foreach (config_get_path('installedpackages/pfblockernglistsv4/config', []) as $i => $g) {
                if (is_array($g) && strcasecmp($g['aliasname'] ?? '', $entry['aliasname']) === 0) {
                    return $i;
                }
            }
            return null;
    }
    return null;
}

function acx_path(string $kind): string
{
    return ['alias' => 'aliases/alias', 'rule' => 'filter/rule', 'nat' => 'nat/rule', 'pfb_ipv4' => 'installedpackages/pfblockernglistsv4/config'][$kind];
}

/** The fields this deployment sets, to decide "already set". */
function acx_same(string $kind, array $current, array $entry): bool
{
    $norm = function ($v) use (&$norm) {
        if (is_array($v)) {
            ksort($v);
            return array_map($norm, $v);
        }
        return (string) $v;
    };
    foreach ($entry as $k => $v) {
        if (in_array($k, ['detail', 'created', 'updated', 'tracker'], true)) {
            continue;
        }
        if ($norm($current[$k] ?? null) !== $norm($v)) {
            return false;
        }
    }
    // Flags this deployment doesn't set must also be off (e.g. a disabled rule isn't "already set").
    if (in_array($kind, ['rule', 'nat'], true) && isset($current['disabled'])) {
        return false;
    }
    if ($kind === 'rule' && (isset($current['log']) !== isset($entry['log']) || isset($current['protocol']) !== isset($entry['protocol']))) {
        return false;
    }
    return true;
}

/* --------------------------------------------------------------- planning */

function acx_plan(array $items): array
{
    $pfb = acx_pfb();
    $aliases = acx_alias_names($items);
    $plan = [];
    $seen = [];
    foreach (array_values($items) as $n => $it) {
        $kind = (string) ($it['kind'] ?? '');
        $p = ['n' => $n, 'kind' => $kind, 'label' => (string) ($it['label'] ?? ''), 'status' => 'error', 'messages' => []];
        if ($kind === 'pfb_ipv4' && (!$pfb['installed'] || !$pfb['compatible'])) {
            $p['status'] = 'needs_package';
            $p['messages'][] = $pfb['installed']
                ? "pfBlockerNG {$pfb['version']} is too old for this; version 3 or newer is needed."
                : 'pfBlockerNG is not installed on this firewall.';
            $plan[] = $p;
            continue;
        }
        [$entry, $errors] = acx_build($it, $aliases);
        if ($errors) {
            $p['messages'] = $errors;
            $plan[] = $p;
            continue;
        }
        $key = $kind . '|' . strtolower(json_encode([$entry['name'] ?? $entry['aliasname'] ?? null, $entry['interface'] ?? null, $entry['descr'] ?? null]));
        if (isset($seen[$key])) {
            $p['messages'][] = 'This deployment has the same item twice.';
            $plan[] = $p;
            continue;
        }
        $seen[$key] = true;
        $index = acx_find($kind, $entry);
        if ($index === null) {
            $p['status'] = 'create';
        } else {
            $current = config_get_path(acx_path($kind) . '/' . $index, []);
            $p['status'] = acx_same($kind, $current, $entry) ? 'same' : 'update';
        }
        $p['entry'] = $entry;
        $plan[] = $p;
    }
    return $plan;
}

function acx_summary(array $plan): array
{
    $out = [];
    foreach ($plan as $p) {
        unset($p['entry']);
        $out[] = $p;
    }
    return $out;
}

/* ------------------------------------------------------------- applying */

/** pfB_ aliases used by rules or port forwards in this plan that aren't in the firewall's aliases yet. */
function acx_pending_pfb_aliases(array $plan): array
{
    $have = [];
    foreach (config_get_path('aliases/alias', []) as $a) {
        if (is_array($a) && isset($a['name'])) {
            $have[strtolower($a['name'])] = true;
        }
    }
    $need = [];
    foreach ($plan as $p) {
        if (!in_array($p['kind'], ['rule', 'nat'], true) || empty($p['entry'])) {
            continue;
        }
        foreach (['source', 'destination'] as $side) {
            $addr = (string) ($p['entry'][$side]['address'] ?? '');
            if (stripos($addr, 'pfB_') === 0 && !isset($have[strtolower($addr)])) {
                $need[strtolower($addr)] = $addr;
            }
        }
        $target = (string) ($p['entry']['target'] ?? '');
        if (stripos($target, 'pfB_') === 0 && !isset($have[strtolower($target)])) {
            $need[strtolower($target)] = $target;
        }
    }
    return array_values($need);
}

function acx_insert_rule(array $rules, array $rule, string $placement): array
{
    $positions = [];
    foreach ($rules as $i => $r) {
        if (is_array($r) && empty($r['floating']) && ($r['interface'] ?? '') === $rule['interface']) {
            $positions[] = $i;
        }
    }
    if (!$positions) {
        $rules[] = $rule;
        return array_values($rules);
    }
    $at = $placement === 'bottom' ? end($positions) + 1 : $positions[0];
    array_splice($rules, $at, 0, [$rule]);
    return array_values($rules);
}

function acx_nat_rule(array $nat, string $assoc): array
{
    $dst = ['address' => $nat['target']];
    if (($nat['local-port'] ?? '') !== '') {
        $dst['port'] = $nat['local-port'];
    }
    return ['type' => 'pass', 'interface' => $nat['interface'], 'ipprotocol' => 'inet', 'protocol' => $nat['protocol'],
        'source' => $nat['source'], 'destination' => $dst, 'descr' => 'NAT ' . $nat['descr'], 'associated-rule-id' => $assoc,
        'tracker' => (string) (time() . random_int(100, 999)), 'created' => acx_created()];
}

function acx_find_assoc(string $assoc): ?int
{
    foreach (config_get_path('filter/rule', []) as $i => $r) {
        if (is_array($r) && ($r['associated-rule-id'] ?? '') === $assoc) {
            return $i;
        }
    }
    return null;
}

/** pf can load the generated rules? Returns an error message or null. */
function acx_rules_error(): ?string
{
    $out = [];
    $rc = 0;
    exec('/sbin/pfctl -nf /tmp/rules.debug 2>&1', $out, $rc);
    if ($rc !== 0) {
        return 'The firewall could not load the new rules: ' . substr(trim(implode(' ', $out)), 0, 400);
    }
    return null;
}

function acx_sections(): array
{
    return [
        'aliases/alias' => config_get_path('aliases/alias', []),
        'filter/rule' => config_get_path('filter/rule', []),
        'nat/rule' => config_get_path('nat/rule', []),
        'installedpackages/pfblockernglistsv4/config' => config_get_path('installedpackages/pfblockernglistsv4/config', null),
    ];
}

function acx_restore_sections(array $sections): void
{
    foreach ($sections as $path => $value) {
        if ($value === null) {
            config_del_path($path);
        } else {
            config_set_path($path, $value);
        }
    }
}

function acx_pfb_update(): ?string
{
    if (!file_exists(ACX_PFB_INC)) {
        return null;
    }
    require_once(ACX_PFB_INC);
    if (function_exists('pfb_global')) {
        pfb_global();
    }
    global $pfb;
    $ps = [];
    exec('/bin/ps -wwx', $ps);
    if (preg_grep('/pfblockerng[.]php\s+?(cron|update|updateip|updatednsbl)/', $ps)) {
        return 'A pfBlockerNG update was already running; the new list is picked up by the next update.';
    }
    $log = $pfb['log'] ?? '/var/log/pfblockerng/pfblockerng.log';
    install_cron_job('pfblockerng.php cron', false);
    mwexec_bg('/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update >> ' . escapeshellarg($log) . ' 2>&1');
    return null;
}

switch ($action) {
    case 'check':
        $items = (array) ($args['items'] ?? []);
        $plan = acx_plan($items);
        acx_out(['ok' => true, 'version' => acx_version(), 'pfblockerng' => acx_pfb(),
            'interfaces' => array_values(acx_interfaces()), 'plan' => acx_summary($plan)]);
        break;

    case 'apply':
        $items = (array) ($args['items'] ?? []);
        $label = substr(preg_replace('/[^\w .#:()-]/', '', (string) ($args['label'] ?? 'deployment')), 0, 80);
        $plan = acx_plan($items);
        foreach ($plan as $p) {
            if (in_array($p['status'], ['error', 'needs_package'], true)) {
                acx_fail('Nothing was changed: a change doesn\'t fit this firewall.', ['plan' => acx_summary($plan)]);
            }
        }

        $before = acx_sections();
        $undo = [];
        $pfbChanged = false;
        foreach ($plan as $p) {
            if ($p['status'] === 'same') {
                continue;
            }
            $kind = $p['kind'];
            $entry = $p['entry'];
            $index = acx_find($kind, $entry);
            $path = acx_path($kind);
            $list = config_get_path($path, []);
            if (!is_array($list)) {
                $list = [];
            }
            $old = $index !== null ? $list[$index] : null;
            if ($kind === 'rule') {
                $entry['tracker'] = $old['tracker'] ?? (string) (time() . random_int(100, 999));
                $entry['created'] = $old['created'] ?? acx_created();
                if ($old !== null) {
                    $entry['updated'] = acx_created();
                }
            } elseif ($kind === 'nat') {
                $entry['associated-rule-id'] = $old['associated-rule-id'] ?? ('nat_' . uniqid('', true));
                $entry['associated-rule-id'] = preg_replace('/[^A-Za-z0-9_]/', '', $entry['associated-rule-id']);
                $entry['created'] = $old['created'] ?? acx_created();
            } elseif ($kind === 'alias' && $old !== null) {
                // Keep fields pfSense set that this deployment doesn't manage.
                $entry = $entry + $old;
            } elseif ($kind === 'pfb_ipv4') {
                $entry = $entry + ($old ?? []);
                $pfbChanged = true;
            }

            if ($index === null) {
                if ($kind === 'rule') {
                    $list = acx_insert_rule($list, $entry, (string) ($items[$p['n']]['placement'] ?? 'top'));
                } else {
                    $list[] = $entry;
                }
            } else {
                $list[$index] = $entry;
            }
            config_set_path($path, array_values($list));

            if ($kind === 'nat') {
                // The linked pass rule, like pfSense's "Add associated filter rule".
                $assoc = $entry['associated-rule-id'];
                $rules = config_get_path('filter/rule', []);
                $ri = acx_find_assoc($assoc);
                $linked = acx_nat_rule($entry, $assoc);
                if ($ri === null) {
                    $rules = acx_insert_rule($rules, $linked, 'top');
                } else {
                    $linked['tracker'] = $rules[$ri]['tracker'] ?? $linked['tracker'];
                    $linked['created'] = $rules[$ri]['created'] ?? $linked['created'];
                    $rules[$ri] = $linked;
                }
                config_set_path('filter/rule', array_values($rules));
            }

            $undo[] = ['kind' => $kind, 'key' => ['name' => $entry['name'] ?? $entry['aliasname'] ?? null, 'interface' => $entry['interface'] ?? null, 'descr' => $entry['descr'] ?? null],
                'assoc' => $entry['associated-rule-id'] ?? null, 'before' => $old];
        }

        // A rule or port forward that uses a pfBlockerNG list's alias (pfB_...) before pfBlockerNG has made it:
        // add an empty alias of that name so the firewall can load the rules. pfBlockerNG fills it (and manages
        // it from then on) at its next update, so until then the rule matches nobody.
        $changedItems = count($undo);
        if ($undo) {
            foreach (acx_pending_pfb_aliases($plan) as $alias) {
                $aliasesNow = config_get_path('aliases/alias', []);
                $aliasesNow[] = ['name' => $alias, 'type' => 'host', 'address' => '', 'descr' => 'pfBlockerNG list, filled at its next update (' . ACX_TAG . ')'];
                config_set_path('aliases/alias', array_values($aliasesNow));
                $undo[] = ['kind' => 'alias', 'key' => ['name' => $alias, 'interface' => null, 'descr' => null], 'assoc' => null, 'before' => null];
            }
        }

        if (!$undo) {
            acx_out(['ok' => true, 'changed' => 0, 'undo' => [], 'plan' => acx_summary($plan), 'message' => 'Everything was already set.']);
        }

        write_config(ACX_TAG . " {$label}: {$changedItems} change(s)");
        filter_configure_sync();
        if ($error = acx_rules_error()) {
            acx_restore_sections($before);
            write_config(ACX_TAG . " {$label}: undone, the firewall could not load the new rules");
            filter_configure_sync();
            acx_fail($error, ['undone' => true, 'plan' => acx_summary($plan)]);
        }
        $note = $pfbChanged ? acx_pfb_update() : null;
        acx_out(['ok' => true, 'changed' => $changedItems, 'undo' => $undo, 'plan' => acx_summary($plan), 'pfb_update' => $pfbChanged, 'note' => $note]);
        break;

    case 'undo':
        $label = substr(preg_replace('/[^\w .#:()-]/', '', (string) ($args['label'] ?? 'deployment')), 0, 80);
        $undo = array_reverse((array) ($args['undo'] ?? []));
        $before = acx_sections();
        $done = 0;
        $pfbChanged = false;
        foreach ($undo as $u) {
            $kind = (string) ($u['kind'] ?? '');
            if (!in_array($kind, ['alias', 'rule', 'nat', 'pfb_ipv4'], true)) {
                continue;
            }
            $key = (array) ($u['key'] ?? []);
            $find = $kind === 'pfb_ipv4' ? ['aliasname' => (string) $key['name']] : ['name' => (string) ($key['name'] ?? ''), 'interface' => (string) ($key['interface'] ?? ''), 'descr' => (string) ($key['descr'] ?? '')];
            $index = acx_find($kind, $find);
            $path = acx_path($kind);
            $list = config_get_path($path, []);
            if (!is_array($list)) {
                $list = [];
            }
            $old = $u['before'] ?? null;
            if ($old === null) {
                if ($index !== null) {
                    unset($list[$index]);
                    $done++;
                }
            } elseif ($index !== null) {
                $list[$index] = $old;
                $done++;
            } else {
                $list[] = $old;
                $done++;
            }
            config_set_path($path, array_values($list));
            if ($kind === 'nat' && !empty($u['assoc'])) {
                $rules = config_get_path('filter/rule', []);
                $ri = acx_find_assoc((string) $u['assoc']);
                if ($old === null && $ri !== null) {
                    unset($rules[$ri]);
                    config_set_path('filter/rule', array_values($rules));
                } elseif ($old !== null && $ri !== null) {
                    $rules[$ri] = acx_nat_rule($old, (string) $u['assoc']) + ['tracker' => $rules[$ri]['tracker'] ?? ''];
                    config_set_path('filter/rule', array_values($rules));
                }
            }
            if ($kind === 'pfb_ipv4') {
                $pfbChanged = true;
            }
        }
        if ($done === 0) {
            acx_out(['ok' => true, 'undone' => 0, 'message' => 'Nothing from this deployment was left to undo.']);
        }
        write_config(ACX_TAG . " {$label}: undone");
        filter_configure_sync();
        if ($error = acx_rules_error()) {
            acx_restore_sections($before);
            write_config(ACX_TAG . " {$label}: undo reverted, the firewall could not load the rules");
            filter_configure_sync();
            acx_fail('Undo was not possible: ' . $error);
        }
        if ($pfbChanged) {
            acx_pfb_update();
        }
        acx_out(['ok' => true, 'undone' => $done]);
        break;

    default:
        acx_fail('Unknown action.');
}

<?php

namespace App\Services\Vpn;

use App\Services\PfSenseApiService;

/**
 * WireGuard on pfSense through the pfSense REST API package (pfrest, API v2) that AdmixCentral already uses.
 *
 * API user privileges needed (in addition to what AdmixCentral already uses):
 *   api-v2-vpn-wireguard-settings-patch, -tunnels-get, -tunnel-post, -peers-get, -peer-post, -peer-delete, -apply-post,
 *   api-v2-interfaces-get, api-v2-interface-post, api-v2-interface-apply-post,
 *   api-v2-firewall-aliases-get, -alias-post, -rule-post, -apply-post,
 *   api-v2-system-packages-get, api-v2-system-package-post (to install the WireGuard package when it's missing).
 */
class PfSenseWireGuardDriver implements WireGuardDriver
{
    private const DESCR = 'CFBTEL VPN';
    private const ALIAS = 'CFBVPN_Private_Nets';
    public const PACKAGE = 'pfSense-pkg-WireGuard';
    /** Installing a package downloads it on the firewall: allow a few minutes. */
    public const INSTALL_TIMEOUT = 300;
    private const READY_TRIES = 12;
    /** Seconds between "is WireGuard ready yet?" checks after installing (tests set 0). */
    public static int $readyWait = 5;

    public function __construct(private PfSenseApiService $api)
    {
    }

    private function data(array|null $res): array
    {
        return is_array($res['data'] ?? null) ? $res['data'] : [];
    }

    public function interfaces(): array
    {
        return array_map(fn ($i) => [
            'id' => (string) ($i['id'] ?? ''),
            'descr' => (string) ($i['descr'] ?? $i['id'] ?? ''),
            'ipaddr' => is_string($i['ipaddr'] ?? null) ? $i['ipaddr'] : null,
            'subnet' => is_numeric($i['subnet'] ?? null) ? (int) $i['subnet'] : null,
        ], $this->data($this->api->get('/interfaces', ['limit' => 0])));
    }

    /** pfrest answers 424 "requires the 'pfSense-pkg-WireGuard' package but it is not installed". */
    private static function isMissingPackage(\Throwable $e): bool
    {
        return str_contains($e->getMessage(), self::PACKAGE) && str_contains($e->getMessage(), 'not installed');
    }

    /**
     * Is pfSense's WireGuard package installed? Asks the firewall's installed-package list first (a WireGuard
     * endpoint can answer before the package is really there), then the WireGuard settings endpoint.
     */
    public function packageInstalled(): bool
    {
        try {
            $names = array_map(fn ($p) => (string) ($p['name'] ?? ''), $this->data($this->api->get('/system/packages', ['limit' => 0])));
            if (in_array(self::PACKAGE, $names, true)) {
                return true;
            }
            if ($names !== []) {
                return false; // the list works and WireGuard isn't on it
            }
        } catch (\Throwable) {
            // no privilege for the package list: fall back to asking WireGuard itself
        }
        try {
            $this->api->get('/vpn/wireguard/settings');
            return true;
        } catch (\Throwable $e) {
            if (self::isMissingPackage($e)) {
                return false;
            }
            throw $e;
        }
    }

    /** Install pfSense's WireGuard package when it's missing (System → Package Manager → WireGuard). @return bool installed now */
    public function ensurePackage(bool $force = false): bool
    {
        if (!$force && $this->packageInstalled()) {
            return false;
        }
        try {
            $this->api->setApiTimeout(self::INSTALL_TIMEOUT);
            $this->api->post('/system/package', ['name' => self::PACKAGE]);
        } catch (\Throwable $e) {
            $why = $e->getCode() === 403
                ? 'the AdmixCentral API user needs the "api-v2-system-package-post" privilege'
                : $e->getMessage();
            throw new VpnException("Couldn't install the WireGuard package on this firewall ({$why}). Install it in pfSense under System → Package Manager → Available Packages → WireGuard, then try again.");
        } finally {
            $this->api->setApiTimeout(20);
        }
        // pfSense can take a little while before the new package answers.
        for ($try = 0; $try < self::READY_TRIES; $try++) {
            if ($this->wireGuardAnswers()) {
                return true;
            }
            if (self::$readyWait > 0) {
                sleep(self::$readyWait);
            }
        }
        throw new VpnException('The WireGuard package was installed but pfSense doesn\'t answer for it yet. Wait a minute and click Create again.');
    }

    private function wireGuardAnswers(): bool
    {
        try {
            $this->api->get('/vpn/wireguard/settings');
            return true;
        } catch (\Throwable $e) {
            if (self::isMissingPackage($e)) {
                return false;
            }
            throw $e;
        }
    }

    /** Runs a WireGuard call; if pfSense says the package is missing, installs it and tries once more. */
    private function withPackage(callable $call)
    {
        try {
            return $call();
        } catch (\Throwable $e) {
            if (!self::isMissingPackage($e)) {
                throw $e;
            }
            $this->ensurePackage(true);
            return $call();
        }
    }

    public function tunnels(): array
    {
        try {
            $rows = $this->data($this->api->get('/vpn/wireguard/tunnels', ['limit' => 0]));
        } catch (\Throwable $e) {
            if (self::isMissingPackage($e)) {
                return []; // no WireGuard package yet: no tunnels (setup installs it)
            }
            throw $e;
        }
        return array_map(fn ($t) => [
            'ref' => (string) ($t['name'] ?? ''),
            'name' => (string) ($t['descr'] ?? $t['name'] ?? ''),
            'listen_port' => (int) ($t['listenport'] ?? 0),
            'public_key' => (string) ($t['publickey'] ?? ''),
        ], $rows);
    }

    public function setup(array $input): array
    {
        $log = [];
        $bits = (int) explode('/', $input['subnet'])[1];
        $gateway = WireGuard::firstHost($input['subnet']);

        if ($this->ensurePackage()) {
            $log[] = 'WireGuard package installed';
        }
        $this->withPackage(fn () => $this->api->patch('/vpn/wireguard/settings', ['enable' => true, 'keep_conf' => true]));
        $log[] = 'WireGuard enabled';

        foreach ($this->tunnels() as $t) {
            if ($t['name'] === self::DESCR) {
                throw new VpnException("A \"" . self::DESCR . "\" tunnel ({$t['ref']}) already exists on this firewall. Use \"Adopt existing tunnel\" instead.");
            }
        }
        $keys = WireGuard::keyPair();
        $this->api->post('/vpn/wireguard/tunnel', [
            'enabled' => true,
            'descr' => self::DESCR,
            'listenport' => (string) $input['listen_port'],
            'privatekey' => $keys['private'],
            'mtu' => 1420,
        ]);
        $this->api->post('/vpn/wireguard/apply', []);
        $tunnel = collect($this->tunnels())->firstWhere('name', self::DESCR);
        if (!$tunnel) {
            throw new VpnException('The tunnel was not created.');
        }
        $log[] = "Tunnel {$tunnel['ref']} created on UDP {$input['listen_port']}";

        $iface = $this->data($this->api->post('/interface', [
            'if' => $tunnel['ref'],
            'enable' => true,
            'descr' => 'CFBTEL_VPN',
            'typev4' => 'static',
            'ipaddr' => $gateway,
            'subnet' => $bits,
            'typev6' => 'none',
            'mtu' => 1420,
        ]));
        $this->api->post('/interface/apply', []);
        $interfaceId = $iface['id'] ?? null;
        if (!$interfaceId) {
            $all = $this->data($this->api->get('/interfaces', ['limit' => 0]));
            $interfaceId = collect($all)->firstWhere('if', $tunnel['ref'])['id'] ?? null;
        }
        if (!$interfaceId) {
            throw new VpnException('Assigning the WireGuard interface failed.');
        }
        $log[] = "Interface {$interfaceId} = {$gateway}/{$bits}";

        $aliases = array_column($this->data($this->api->get('/firewall/aliases', ['limit' => 0])), 'name');
        if (!in_array(self::ALIAS, $aliases, true)) {
            $this->api->post('/firewall/alias', [
                'name' => self::ALIAS,
                'type' => 'network',
                'descr' => 'RFC1918 networks (CFBTEL VPN)',
                'address' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
                'detail' => ['RFC1918', 'RFC1918', 'RFC1918'],
            ]);
            $log[] = 'Alias ' . self::ALIAS . ' created';
        }

        $rule = fn (array $r) => $this->api->post('/firewall/rule', array_merge([
            'interface' => [$interfaceId], 'ipprotocol' => 'inet', 'source' => $input['subnet'], 'statetype' => 'keep state',
        ], $r));
        $rule(['type' => 'pass', 'protocol' => 'tcp/udp', 'destination' => '(self)', 'destination_port' => '53', 'descr' => 'CFBTEL VPN: DNS to firewall']);
        $rule(['type' => 'block', 'destination' => '(self)', 'descr' => 'CFBTEL VPN: block firewall admin']);
        $rule(['type' => 'pass', 'destination' => $input['lan'], 'descr' => "CFBTEL VPN: allow {$input['lan']} network"]);
        $rule(['type' => 'block', 'destination' => self::ALIAS, 'descr' => 'CFBTEL VPN: block other private networks']);
        $rule(['type' => 'pass', 'destination' => 'any', 'descr' => 'CFBTEL VPN: internet (full tunnel)']);
        $log[] = 'VPN interface rules added';

        $this->api->post('/firewall/rule', [
            'type' => 'pass', 'interface' => [$input['wan']], 'ipprotocol' => 'inet', 'protocol' => 'udp',
            'source' => 'any', 'destination' => "{$input['wan']}:ip", 'destination_port' => (string) $input['listen_port'],
            'descr' => 'CFBTEL VPN: WireGuard',
        ]);
        $log[] = "WAN rule for UDP {$input['listen_port']} added";

        $this->api->post('/firewall/apply', []);
        $log[] = 'Firewall rules applied (outbound NAT must be Automatic or Hybrid)';

        return ['ref' => $tunnel['ref'], 'name' => self::DESCR, 'public_key' => $tunnel['public_key'] ?: $keys['public'], 'gateway' => $gateway, 'log' => $log];
    }

    /** Peers with their pfrest ids (list positions). */
    private function rawPeers(string $tunnelRef): array
    {
        $out = [];
        foreach ($this->data($this->api->get('/vpn/wireguard/peers', ['limit' => 0])) as $p) {
            if (($p['tun'] ?? '') !== $tunnelRef) {
                continue;
            }
            $out[] = [
                'id' => (int) ($p['id'] ?? -1),
                'public_key' => (string) ($p['publickey'] ?? ''),
                'name' => (string) ($p['descr'] ?? ''),
                'addresses' => array_map(fn ($a) => (string) ($a['address'] ?? ''), is_array($p['allowedips'] ?? null) ? $p['allowedips'] : []),
            ];
        }
        return $out;
    }

    public function peers(string $tunnelRef): array
    {
        return array_map(fn ($p) => ['public_key' => $p['public_key'], 'name' => $p['name'], 'addresses' => $p['addresses']], $this->rawPeers($tunnelRef));
    }

    public function addPeer(string $tunnelRef, array $peer): void
    {
        $this->api->post('/vpn/wireguard/peer', [
            'enabled' => true,
            'tun' => $tunnelRef,
            // pfSense allows free text: keep the person and device readable on the firewall.
            'descr' => mb_substr("{$peer['name']} {$peer['label']}", 0, 200),
            'publickey' => $peer['public_key'],
            'presharedkey' => $peer['preshared_key'],
            'allowedips' => [['address' => $peer['address'], 'mask' => 32, 'descr' => $peer['name']]],
        ]);
        $this->api->post('/vpn/wireguard/apply', []);
    }

    public function removePeers(string $tunnelRef, array $publicKeys): int
    {
        $want = array_flip($publicKeys);
        // pfrest ids are list positions and shift after each delete, so delete the highest first.
        $doomed = array_filter($this->rawPeers($tunnelRef), fn ($p) => isset($want[$p['public_key']]) && str_starts_with($p['name'], WireGuard::PEER_PREFIX));
        usort($doomed, fn ($a, $b) => $b['id'] <=> $a['id']);
        foreach ($doomed as $p) {
            $this->api->delete('/vpn/wireguard/peer?id=' . $p['id']);
        }
        if ($doomed) {
            $this->api->post('/vpn/wireguard/apply', []);
        }
        return count($doomed);
    }
}

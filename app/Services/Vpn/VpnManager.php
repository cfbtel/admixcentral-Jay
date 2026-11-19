<?php

namespace App\Services\Vpn;

use App\Models\Company;
use App\Models\Firewall;
use App\Models\Vpn\VpnAuditLog;
use App\Models\Vpn\VpnCompany;
use App\Models\Vpn\VpnDevice;
use App\Models\Vpn\VpnSite;
use App\Models\Vpn\VpnUser;
use App\Services\OpnSenseApiService;
use App\Services\PfSenseApiService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/** Devices, removals and the periodic access check. */
class VpnManager
{
    /** @var (\Closure(Firewall): WireGuardDriver)|null */
    private static ?\Closure $driverResolver = null;

    /** Tests swap in fake firewalls. */
    public static function resolveDriversWith(?\Closure $resolver): void
    {
        self::$driverResolver = $resolver;
    }

    public static function driverFor(Firewall $firewall): WireGuardDriver
    {
        if (self::$driverResolver) {
            return (self::$driverResolver)($firewall);
        }
        return $firewall->isOpnSense()
            ? new OpnSenseWireGuardDriver(new OpnSenseApiService($firewall))
            : new PfSenseWireGuardDriver((new PfSenseApiService($firewall))->setApiTimeout(60));
    }

    public function driver(VpnSite $site): WireGuardDriver
    {
        return self::driverFor($site->firewall);
    }

    /** One change at a time per firewall, so two people are never given the same address. */
    private function locked(VpnSite $site, \Closure $fn): mixed
    {
        return Cache::lock("vpn_site:{$site->id}", 120)->block(60, $fn);
    }

    /** @return \Illuminate\Support\Collection<int, VpnSite> */
    public function readySites(int $companyId)
    {
        return VpnSite::with('firewall')->where('company_id', $companyId)->where('status', 'ready')->get()->filter->isReady()->values();
    }

    /**
     * Create a key pair and a peer; return the client configuration (shown once, never stored).
     * With $publicKey (the CFBTEL VPN app made its own key pair), the private key never leaves that computer:
     * config is then null and 'peer' holds what the app needs.
     *
     * @return array{device: VpnDevice, config: ?string, peer: array{address: string, preshared_key: string}}
     */
    public function addDevice(VpnUser $user, VpnSite $site, string $name, ?string $publicKey = null): array
    {
        if ($publicKey !== null && (!WireGuard::isKey($publicKey) || VpnDevice::where('public_key', $publicKey)->exists())) {
            throw new VpnException('This computer\'s key is invalid or already in use. Start the sign-in again from the app.');
        }
        if ($user->activeDevices()->count() >= VpnSettings::maxDevices()) {
            throw new VpnException('You already have ' . VpnSettings::maxDevices() . ' devices. Remove one first.');
        }
        if ($user->activeDevices()->where('vpn_site_id', $site->id)->whereRaw('lower(name) = ?', [strtolower($name)])->exists()) {
            throw new VpnException("You already have a device called \"{$name}\" there.");
        }

        return $this->locked($site, function () use ($user, $site, $name, $publicKey) {
            $driver = $this->driver($site);
            $onFirewall = collect($driver->peers($site->tunnel))->pluck('addresses')->flatten()->all();
            $inDb = VpnDevice::where('vpn_site_id', $site->id)->pluck('address')->all();
            $address = WireGuard::allocate($site->subnet, array_merge($onFirewall, $inDb, [WireGuard::firstHost($site->subnet)]));
            if (!$address) {
                throw new VpnException('No VPN addresses are left at that site. Contact your IT admin.');
            }
            $keys = $publicKey !== null ? ['public' => $publicKey, 'private' => null] : WireGuard::keyPair();
            $psk = WireGuard::presharedKey();
            $device = VpnDevice::create(['vpn_user_id' => $user->id, 'vpn_site_id' => $site->id, 'name' => $name, 'public_key' => $keys['public'], 'address' => $address]);
            try {
                $driver->addPeer($site->tunnel, [
                    'name' => $device->peerName(),
                    'public_key' => $keys['public'],
                    'preshared_key' => $psk,
                    'address' => $address,
                    'label' => "{$user->upn} {$name}",
                ]);
            } catch (\Throwable $e) {
                $device->delete();
                Log::error('VPN: adding a peer failed', ['site' => $site->id, 'error' => $e->getMessage()]);
                throw new VpnException('The office firewall didn\'t accept the new device. Try again shortly.', 0, $e);
            }
            VpnAuditLog::record($site->company_id, $user->upn, "device_added {$name} @ {$site->firewall->name} ({$address})");
            $config = $keys['private'] === null ? null : WireGuard::clientConfig($site->only(['dns', 'server_public_key', 'allowed_ips', 'endpoint']), [
                'label' => preg_replace('/[^\x20-\x7E]/', '?', "{$site->firewall->name} - {$name}"),
                'private_key' => $keys['private'],
                'preshared_key' => $psk,
                'address' => $address,
            ]);
            return ['device' => $device, 'config' => $config, 'peer' => ['address' => $address, 'preshared_key' => $psk]];
        });
    }

    /** Remove one device now. Throws if the firewall can't be reached; the device stays revoked and the sync retries. */
    public function removeDevice(VpnDevice $device, string $actor): void
    {
        $device->update(['revoked_at' => $device->revoked_at ?? now()]);
        $site = $device->site()->with('firewall')->first();
        $this->locked($site, function () use ($device, $site) {
            if ($site->tunnel) {
                $this->driver($site)->removePeers($site->tunnel, [$device->public_key]);
            }
            $device->delete();
        });
        VpnAuditLog::record($site->company_id, $actor, "device_removed {$device->name} @ {$site->firewall->name}");
    }

    /**
     * Take away a person's VPN access: their devices are revoked at once and removed from the firewalls.
     *
     * @return array{removed: int, pending: int}
     */
    public function removeUser(VpnUser $user, string $actor): array
    {
        $devices = $user->devices()->with('site.firewall')->get();
        VpnDevice::whereIn('id', $devices->pluck('id'))->whereNull('revoked_at')->update(['revoked_at' => now()]);
        $companyId = $user->company_id;
        $upn = $user->upn;
        $user->delete(); // devices keep their row (vpn_user_id = null) until the firewall confirms
        $removed = 0;
        $pending = 0;
        foreach ($devices->groupBy('vpn_site_id') as $siteDevices) {
            $site = $siteDevices->first()->site;
            try {
                $this->locked($site, function () use ($site, $siteDevices, &$removed) {
                    if ($site->tunnel) {
                        $this->driver($site)->removePeers($site->tunnel, $siteDevices->pluck('public_key')->all());
                    }
                    VpnDevice::whereIn('id', $siteDevices->pluck('id'))->delete();
                    $removed += $siteDevices->count();
                });
            } catch (\Throwable $e) {
                $pending += $siteDevices->count();
                Log::warning('VPN: removing devices failed; the sync will retry', ['site' => $site->id, 'error' => $e->getMessage()]);
            }
        }
        VpnAuditLog::record($companyId, $actor, "vpn_access_removed {$upn} ({$removed} device(s) removed" . ($pending ? ", {$pending} pending" : '') . ')');
        return ['removed' => $removed, 'pending' => $pending];
    }

    /**
     * Keep the firewalls in line with who may use the VPN:
     *  - people whose Microsoft 365 account was deleted lose access; disabled accounts lose their devices;
     *  - revoked devices (and any cfbvpn- peer AdmixCentral no longer knows) are removed from the firewall.
     * Any Microsoft error stops the account check for that company without removing anything.
     *
     * @return array{removed: int, skipped: bool}
     */
    public function sync(Company $company, ?Microsoft $ms = null): array
    {
        $vc = VpnCompany::where('company_id', $company->id)->first();
        $tenant = $vc?->ms_tenant_id;
        $ms ??= Microsoft::for($vc);
        $skipped = false;
        if ($tenant) {
            $users = VpnUser::where('company_id', $company->id)->where('auth_type', 'microsoft')->whereNotNull('ms_oid')->get();
            $states = [];
            try {
                foreach ($users as $u) {
                    $states[$u->id] = $ms->userStatus($tenant, $u->ms_oid);
                }
            } catch (\Throwable $e) {
                $skipped = true;
                Log::warning('VPN sync: Microsoft unavailable; account check skipped', ['company' => $company->id, 'error' => $e->getMessage()]);
            }
            if (!$skipped) {
                foreach ($users as $u) {
                    $st = $states[$u->id];
                    if ($st === null) {
                        VpnDevice::where('vpn_user_id', $u->id)->whereNull('revoked_at')->update(['revoked_at' => now()]);
                        VpnAuditLog::record($company->id, 'system', "vpn_access_removed {$u->upn} (account deleted in Microsoft 365)");
                        $u->delete();
                    } elseif (!$st['enabled'] && $u->activeDevices()->exists()) {
                        $u->activeDevices()->update(['revoked_at' => now()]);
                        VpnAuditLog::record($company->id, 'system', "devices_revoked {$u->upn} (account disabled in Microsoft 365)");
                    }
                }
            }
        }

        // Microsoft 365 groups: people who came in through a group and left all of the company's groups lose
        // access; anyone who left a firewall's group loses their devices on that firewall.
        if ($tenant && !$skipped && $vc && VpnAccess::usesGroups($vc)) {
            $ids = VpnAccess::groupIds($vc);
            $siteGroups = VpnSite::where('company_id', $company->id)->whereNotNull('access_group_id')->get()
                ->mapWithKeys(fn ($s) => [$s->id => ['group' => strtolower($s->access_group_id), 'name' => $s->access_group_name]]);
            $people = VpnUser::where('company_id', $company->id)->where('auth_type', 'microsoft')->whereNotNull('ms_oid')->get();
            $member = [];
            try {
                foreach ($people as $u) {
                    $member[$u->id] = $ms->memberOf($tenant, $u->ms_oid, $ids);
                }
            } catch (\Throwable $e) {
                $member = null;
                $skipped = true;
                Log::warning('VPN sync: Microsoft groups unavailable; group check skipped', ['company' => $company->id, 'error' => $e->getMessage()]);
            }
            foreach ($member === null ? [] : $people as $u) {
                $in = $member[$u->id];
                if ($u->viaGroup() && !array_intersect($ids, $in)) {
                    VpnDevice::where('vpn_user_id', $u->id)->whereNull('revoked_at')->update(['revoked_at' => now()]);
                    VpnAuditLog::record($company->id, 'system', "vpn_access_removed {$u->upn} (no longer in the Microsoft 365 group)");
                    $u->delete();
                    continue;
                }
                foreach ($siteGroups as $siteId => $g) {
                    if (!in_array($g['group'], $in, true)) {
                        $n = VpnDevice::where('vpn_user_id', $u->id)->where('vpn_site_id', $siteId)->whereNull('revoked_at')->update(['revoked_at' => now()]);
                        if ($n) {
                            VpnAuditLog::record($company->id, 'system', "devices_revoked {$u->upn} ({$n}, not in group {$g['name']})");
                        }
                    }
                }
            }
        }

        $removed = 0;
        foreach ($this->readySites($company->id) as $site) {
            try {
                $removed += $this->locked($site, function () use ($site) {
                    $driver = $this->driver($site);
                    $keep = VpnDevice::where('vpn_site_id', $site->id)->whereNull('revoked_at')->pluck('public_key')->flip();
                    $doomed = collect($driver->peers($site->tunnel))
                        ->filter(fn ($p) => str_starts_with($p['name'], WireGuard::PEER_PREFIX) && !isset($keep[$p['public_key']]))
                        ->pluck('public_key')->all();
                    $n = $doomed ? $driver->removePeers($site->tunnel, $doomed) : 0;
                    VpnDevice::where('vpn_site_id', $site->id)->whereNotNull('revoked_at')->delete();
                    return $n;
                });
            } catch (\Throwable $e) {
                Log::error('VPN sync: a site could not be checked', ['site' => $site->id, 'error' => $e->getMessage()]);
            }
        }
        if ($removed) {
            VpnAuditLog::record($company->id, 'system', "sync_removed {$removed} device(s) from the firewall");
        }
        return ['removed' => $removed, 'skipped' => $skipped];
    }
}

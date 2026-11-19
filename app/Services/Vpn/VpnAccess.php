<?php

namespace App\Services\Vpn;

use App\Models\Vpn\VpnCompany;
use App\Models\Vpn\VpnSite;
use App\Models\Vpn\VpnUser;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

/**
 * Who may use which firewall, with Microsoft 365 groups:
 *
 *  - Company group (optional): its members get VPN access without being added one by one.
 *    People added by hand keep access as before.
 *  - Firewall group (optional): only members of that group can use that firewall. Firewalls without
 *    a group are open to everyone with VPN access in the company. Members of a firewall's group also
 *    get VPN access for that firewall even when they aren't in the company group.
 *  - Email-and-password accounts aren't in Microsoft 365: they can use firewalls without a group only.
 *
 * Membership (including nested groups) comes from Microsoft Graph and is cached for a few minutes;
 * adding a device and the 15-minute sync always ask Microsoft again.
 */
class VpnAccess
{
    public const CACHE_SECONDS = 300;

    public function __construct(private VpnManager $vpn)
    {
    }

    /** Every group the company uses: its own and its firewalls'. @return string[] */
    public static function groupIds(VpnCompany $vc): array
    {
        $ids = VpnSite::where('company_id', $vc->company_id)->whereNotNull('access_group_id')->pluck('access_group_id')->all();
        if ($vc->access_group_id) {
            $ids[] = $vc->access_group_id;
        }
        return array_values(array_unique(array_map('strtolower', $ids)));
    }

    public static function usesGroups(VpnCompany $vc): bool
    {
        return self::groupIds($vc) !== [];
    }

    /**
     * Which of the company's groups this Microsoft 365 person is in.
     * @return string[]|null null when Microsoft couldn't be asked
     */
    public function membership(VpnCompany $vc, string $oid, bool $fresh = false): ?array
    {
        $ids = self::groupIds($vc);
        if (!$ids || !$vc->ms_tenant_id) {
            return [];
        }
        $key = 'vpn_groups:' . $vc->company_id . ':' . $oid . ':' . sha1(implode(',', $ids));
        if (!$fresh && is_array($hit = Cache::get($key))) {
            return $hit;
        }
        try {
            $in = Microsoft::for($vc)->memberOf($vc->ms_tenant_id, $oid, $ids);
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::warning('VPN: group membership check failed', ['company' => $vc->company_id, 'error' => $e->getMessage()]);
            return null;
        }
        Cache::put($key, $in, self::CACHE_SECONDS);
        return $in;
    }

    /** Does group membership alone give this person VPN access (company group or any firewall's group)? */
    public static function grantsAccess(VpnCompany $vc, array $membership): bool
    {
        return array_intersect(self::groupIds($vc), $membership) !== [];
    }

    /** The firewalls this person can use. @return Collection<int, VpnSite> */
    public function sitesFor(VpnUser $user, bool $fresh = false): Collection
    {
        $sites = $this->vpn->readySites($user->company_id);
        if ($sites->every(fn (VpnSite $s) => !$s->access_group_id)) {
            return $sites;
        }
        $in = [];
        if (!$user->isLocal() && $user->ms_oid && ($vc = VpnCompany::where('company_id', $user->company_id)->first())) {
            $in = $this->membership($vc, $user->ms_oid, $fresh) ?? []; // Microsoft down: only firewalls without a group
        }
        return $sites->filter(fn (VpnSite $s) => !$s->access_group_id || in_array(strtolower($s->access_group_id), $in, true))->values();
    }
}

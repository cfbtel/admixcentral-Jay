<?php

namespace App\Http\Controllers\Vpn;

use App\Http\Controllers\Controller;
use App\Models\Company;
use App\Models\Firewall;
use App\Models\Vpn\VpnAuditLog;
use App\Models\Vpn\VpnCompany;
use App\Models\Vpn\VpnDevice;
use App\Models\Vpn\VpnSite;
use App\Models\Vpn\VpnUser;
use App\Services\Vpn\Microsoft;
use App\Services\Vpn\VpnException;
use App\Services\Vpn\VpnManager;
use App\Services\Vpn\VpnSettings;
use App\Services\Vpn\WireGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;

/**
 * A company's VPN in the AdmixCentral console (Companies → company → VPN).
 * Global admins and that company's admins manage it; other company users can look.
 */
class CompanyVpnController extends Controller
{
    public function __construct(private VpnManager $vpn, private \App\Services\Vpn\VpnAccounts $accounts)
    {
    }

    /** The company's own Microsoft app if it has one, otherwise CFBTEL's shared app. */
    private function microsoft(VpnCompany $vc): Microsoft
    {
        return Microsoft::for($vc);
    }

    private function canManage(Request $request, Company $company): bool
    {
        $u = $request->user();
        return $u->isGlobalAdmin() || ($u->isCompanyAdmin() && (int) $u->company_id === (int) $company->id);
    }

    private function authorizeManage(Request $request, Company $company): void
    {
        abort_unless($this->canManage($request, $company), 403, 'Only global admins and this company\'s admins can change its VPN.');
    }

    private function actor(Request $request): string
    {
        return $request->user()->email;
    }

    public function show(Request $request, Company $company)
    {
        $vc = VpnCompany::forCompany($company);
        $q = trim((string) $request->query('q', ''));
        $results = null;
        $searchError = null;
        if ($vc->ms_tenant_id && ($q !== '' || $request->has('search')) && $this->canManage($request, $company)) {
            try {
                $have = VpnUser::where('company_id', $company->id)->pluck('ms_oid')->flip();
                $results = collect($this->microsoft($vc)->searchUsers($vc->ms_tenant_id, $q))->filter(fn ($u) => $u['enabled'] && !isset($have[$u['oid']]))->values();
            } catch (\Throwable $e) {
                $searchError = $e instanceof VpnException ? $e->getMessage() : 'Couldn\'t search Microsoft 365.';
            }
        }
        $consentUrl = null;
        $consentError = null;
        if (!$vc->hasOwnApp()) {
            try {
                $state = Crypt::encryptString(json_encode(['c' => $company->id, 'exp' => time() + 7 * 86400]));
                $consentUrl = Microsoft::for(null)->adminConsentUrl(VpnSettings::portalUrl('/vpn/consent/callback'), $state);
            } catch (VpnException $e) {
                $consentError = 'CFBTEL\'s shared Microsoft app isn\'t set up. Use this company\'s own Microsoft app below, or set up the shared app in VPN settings.';
            }
        }
        $setupReady = \App\Services\Vpn\MicrosoftSetup::make()->configured();
        $setupLink = $setupReady && $this->canManage($request, $company) ? MicrosoftSetupController::link($company, $this->actor($request)) : null;
        $sites = VpnSite::with('firewall')->where('company_id', $company->id)->get()->keyBy('firewall_id');

        return view('vpn.admin.company', [
            'company' => $company,
            'vc' => $vc,
            'firewalls' => Firewall::where('company_id', $company->id)->orderBy('name')->get(),
            'sites' => $sites,
            'users' => VpnUser::where('company_id', $company->id)->withCount('activeDevices')->orderBy('name')->get(),
            'devices' => VpnDevice::with(['user', 'site.firewall'])->whereIn('vpn_site_id', $sites->pluck('id'))->orderByDesc('created_at')->get(),
            'audit' => VpnAuditLog::where('company_id', $company->id)->orderByDesc('id')->limit(40)->get(),
            'q' => $q,
            'results' => $results,
            'searchError' => $searchError,
            'consentUrl' => $consentUrl,
            'consentError' => $consentError,
            'setupReady' => $setupReady,
            'setupLink' => $setupLink,
            'canManage' => $this->canManage($request, $company),
            'portalUrl' => VpnSettings::portalUrl('/vpn'),
            'callbackUrl' => VpnSettings::portalUrl('/vpn/callback'),
        ]);
    }

    // ---- people ----

    public function addUser(Request $request, Company $company)
    {
        $this->authorizeManage($request, $company);
        $oid = strtolower((string) $request->input('oid'));
        $vc = VpnCompany::forCompany($company);
        if (!$vc->ms_tenant_id || !Microsoft::isGuid($oid)) {
            return back()->with('error', 'Pick someone from the search results.');
        }
        if (VpnUser::where('company_id', $company->id)->where('ms_oid', $oid)->exists()) {
            return back()->with('error', 'That person already has VPN access.');
        }
        try {
            $u = $this->microsoft($vc)->userStatus($vc->ms_tenant_id, $oid); // name and UPN come from Microsoft, never from the form
        } catch (\Throwable $e) {
            return back()->with('error', $e instanceof VpnException ? $e->getMessage() : 'Couldn\'t reach Microsoft 365.');
        }
        if (!$u || !$u['enabled']) {
            return back()->with('error', 'That account doesn\'t exist or is disabled in this company\'s Microsoft 365.');
        }
        if (VpnUser::where('auth_type', 'local')->where('upn', $u['upn'])->exists()) {
            return back()->with('error', 'That email already has an email-and-password VPN account. Remove it first.');
        }
        VpnUser::create([
            'company_id' => $company->id,
            'auth_type' => 'microsoft',
            'ms_oid' => $oid,
            'upn' => $u['guest'] && $u['mail'] ? strtolower($u['mail']) : $u['upn'],
            'name' => $u['name'],
            'added_by' => $this->actor($request),
        ]);
        VpnAuditLog::record($company->id, $this->actor($request), "vpn_access_given {$u['upn']}");
        return redirect()->route('vpn.company', $company)->with('success', "{$u['name']} can now sign in at the VPN page and add devices.");
    }

    /** Email domains (all companies) and, optionally, the company's own Microsoft app. */
    public function saveMicrosoft(Request $request, Company $company)
    {
        $this->authorizeManage($request, $company);
        $vc = VpnCompany::forCompany($company);
        $v = $request->validate([
            'email_domains' => ['nullable', 'string', 'max:500'],
            'ms_tenant_id' => ['nullable', 'string', 'max:36'],
            'ms_client_id' => ['nullable', 'string', 'max:36'],
            'ms_client_secret' => ['nullable', 'string', 'max:300'],
        ]);
        $domains = array_values(array_unique(array_filter(array_map(fn ($d) => strtolower(trim(ltrim(trim($d), '@'))), preg_split('/[\s,;]+/', (string) ($v['email_domains'] ?? ''))))));
        foreach ($domains as $d) {
            if (!preg_match('/^(?=.{3,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/', $d)) {
                return back()->withErrors(['email_domains' => "“{$d}” isn't a domain name."])->withInput();
            }
            $other = VpnCompany::where('id', '!=', $vc->id)->get()->first(fn ($o) => in_array($d, $o->domains(), true));
            if ($other) {
                return back()->withErrors(['email_domains' => "{$d} is already used by another company."])->withInput();
            }
        }

        $tenant = strtolower(trim((string) ($v['ms_tenant_id'] ?? '')));
        $client = strtolower(trim((string) ($v['ms_client_id'] ?? '')));
        $secret = (string) ($v['ms_client_secret'] ?? '');
        $ownApp = $tenant !== '' || $client !== '' || $secret !== '';
        if ($ownApp) {
            if (!Microsoft::isGuid($tenant) || !Microsoft::isGuid($client)) {
                return back()->withErrors(['ms_client_id' => 'Enter the Directory (tenant) ID and the Application (client) ID from the company\'s app registration.'])->withInput();
            }
            if ($secret === '' && !($vc->hasOwnApp() && $vc->ms_client_id === $client)) {
                return back()->withErrors(['ms_client_secret' => 'Enter the client secret.'])->withInput();
            }
            if (VpnCompany::where('ms_tenant_id', $tenant)->where('id', '!=', $vc->id)->exists()) {
                return back()->withErrors(['ms_tenant_id' => 'This Microsoft 365 tenant is already linked to another company.'])->withInput();
            }
            if ($vc->ms_tenant_id && $vc->ms_tenant_id !== $tenant && VpnUser::where('company_id', $company->id)->exists()) {
                return back()->withErrors(['ms_tenant_id' => 'This company is linked to another tenant and already has VPN people. Remove them first.'])->withInput();
            }
        }

        $vc->email_domains = $domains ? implode(',', $domains) : null;
        if ($ownApp) {
            if ($vc->ms_client_id !== $client || $secret !== '') {
                // Entered by hand: the one-click setup's details no longer describe this app/secret.
                $vc->ms_app_object_id = $vc->ms_client_id === $client ? $vc->ms_app_object_id : null;
                $vc->ms_secret_key_id = null;
                $vc->ms_secret_expires_at = null;
            }
            $vc->ms_tenant_id = $tenant;
            $vc->ms_client_id = $client;
            if ($secret !== '') {
                $vc->ms_client_secret = $secret;
            }
        }
        $vc->save();
        VpnAuditLog::record($company->id, $this->actor($request), 'microsoft_settings ' . ($ownApp ? "own app {$client} in {$tenant}" : 'shared app') . ($domains ? ' domains ' . implode(',', $domains) : ''));

        if ($ownApp) {
            // Check the app can read this tenant's users (User.Read.All with admin consent).
            try {
                $ms = Microsoft::for($vc->fresh());
                $ms->searchUsers($tenant, '');
                $vc->update(['ms_tenant_name' => $ms->tenantName($tenant)]);
            } catch (\Throwable $e) {
                return back()->with('warning', 'Saved, but Microsoft refused the app: ' . $e->getMessage() . ' Check the secret, the User.Read.All application permission and "Grant admin consent".');
            }
            return back()->with('success', 'Saved. Staff of this company now sign in through its own Microsoft app.');
        }
        return back()->with('success', 'Saved.');
    }

    public function removeOwnApp(Request $request, Company $company)
    {
        $this->authorizeManage($request, $company);
        $vc = VpnCompany::forCompany($company);
        $vc->update(['ms_client_id' => null, 'ms_client_secret' => null, 'ms_app_object_id' => null, 'ms_secret_key_id' => null, 'ms_secret_expires_at' => null]);
        VpnAuditLog::record($company->id, $this->actor($request), 'microsoft_own_app_removed');
        return back()->with('success', 'The company\'s own Microsoft app was removed. Sign-in uses CFBTEL\'s shared app again (the company must approve it).');
    }

    // ---- email-and-password accounts (companies without Microsoft Entra) ----

    public function inviteUser(Request $request, Company $company)
    {
        $this->authorizeManage($request, $company);
        $name = trim((string) $request->input('name'));
        $email = \App\Services\Vpn\VpnAccounts::cleanEmail($request->input('email'));
        if ($name === '' || mb_strlen($name) > 120 || !$email) {
            return back()->withErrors(['invite' => 'Enter the person\'s name and a valid email address.'])->withInput();
        }
        if (\App\Services\Vpn\VpnAccounts::emailTaken($email)) {
            return back()->withErrors(['invite' => "{$email} already has VPN access."])->withInput();
        }
        try {
            $this->accounts->invite($company, $name, $email, $this->actor($request));
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::error('VPN: invitation email failed', ['error' => $e->getMessage()]);
            return back()->with('warning', "{$name} was added, but the invitation email couldn't be sent: {$e->getMessage()} Check the email settings, then click Resend invite.");
        }
        return back()->with('success', "Invitation sent to {$email}. The link works for 7 days.");
    }

    public function updateUser(Request $request, Company $company, VpnUser $vpnUser)
    {
        $this->authorizeManage($request, $company);
        abort_unless((int) $vpnUser->company_id === (int) $company->id && $vpnUser->isLocal(), 404);
        $name = trim((string) $request->input('name'));
        $email = \App\Services\Vpn\VpnAccounts::cleanEmail($request->input('email'));
        if ($name === '' || mb_strlen($name) > 120 || !$email) {
            return back()->withErrors(['edit' => 'Enter a name and a valid email address.']);
        }
        if (\App\Services\Vpn\VpnAccounts::emailTaken($email, $vpnUser->id)) {
            return back()->withErrors(['edit' => "{$email} already has VPN access."]);
        }
        $changed = $email !== $vpnUser->upn;
        $vpnUser->update(['name' => $name, 'upn' => $email]);
        VpnAuditLog::record($company->id, $this->actor($request), "vpn_account_updated {$email}" . ($changed ? ' (email changed)' : ''));
        return back()->with('success', "Saved {$name}." . ($changed ? ' They now sign in with the new email address.' : ''));
    }

    public function resendInvite(Request $request, Company $company, VpnUser $vpnUser)
    {
        $this->authorizeManage($request, $company);
        abort_unless((int) $vpnUser->company_id === (int) $company->id && $vpnUser->isLocal(), 404);
        try {
            $this->accounts->sendLink($vpnUser, false);
        } catch (\Throwable $e) {
            return back()->with('error', "The email couldn't be sent: {$e->getMessage()}");
        }
        VpnAuditLog::record($company->id, $this->actor($request), "vpn_invite_resent {$vpnUser->upn}");
        return back()->with('success', "A new link was sent to {$vpnUser->upn}" . ($vpnUser->password ? ' (their current password keeps working until they set a new one).' : '.'));
    }

    public function removeUser(Request $request, Company $company, VpnUser $vpnUser)
    {
        $this->authorizeManage($request, $company);
        abort_unless((int) $vpnUser->company_id === (int) $company->id, 404);
        $r = $this->vpn->removeUser($vpnUser, $this->actor($request));
        return back()->with(
            $r['pending'] ? 'warning' : 'success',
            "{$vpnUser->name} no longer has VPN access. {$r['removed']} device(s) removed" . ($r['pending'] ? "; {$r['pending']} will be removed when the firewall answers (automatic check every 15 minutes)." : '.'),
        );
    }

    public function removeDevice(Request $request, Company $company, VpnDevice $device)
    {
        $this->authorizeManage($request, $company);
        abort_unless((int) $device->site?->company_id === (int) $company->id, 404);
        try {
            $this->vpn->removeDevice($device, $this->actor($request));
            return back()->with('success', "Device “{$device->name}” removed. It can no longer connect.");
        } catch (\Throwable $e) {
            return back()->with('warning', "Device “{$device->name}” was switched off; the firewall didn't answer, so it will be removed at the next automatic check.");
        }
    }

    // ---- firewalls ----

    public function enableFirewall(Request $request, Company $company, Firewall $firewall)
    {
        $this->authorizeManage($request, $company);
        abort_unless((int) $firewall->company_id === (int) $company->id, 404);
        $site = VpnSite::firstOrCreate(['firewall_id' => $firewall->id], ['company_id' => $company->id, 'status' => 'pending']);
        return redirect()->route('vpn.site', [$company, $site]);
    }

    private function siteOf(Company $company, VpnSite $site): VpnSite
    {
        abort_unless((int) $site->company_id === (int) $company->id, 404);
        return $site->load('firewall');
    }

    public function site(Request $request, Company $company, VpnSite $site)
    {
        $site = $this->siteOf($company, $site);
        $data = ['company' => $company, 'site' => $site, 'interfaces' => null, 'tunnels' => null, 'readError' => null, 'suggestedSubnet' => '10.0.70.0/24', 'suggestedHost' => parse_url((string) $site->firewall->url, PHP_URL_HOST) ?: '', 'canManage' => $this->canManage($request, $company), 'log' => session('vpn_log')];
        if (!$site->isReady()) {
            try {
                $driver = $this->vpn->driver($site);
                $data['interfaces'] = $driver->interfaces();
                $data['tunnels'] = $driver->tunnels();
                $used = collect($data['interfaces'])->map(fn ($i) => implode('.', array_slice(explode('.', (string) $i['ipaddr']), 0, 3)))->flip();
                for ($k = 70; $k < 100; $k++) {
                    if (!isset($used["10.0.{$k}"])) {
                        $data['suggestedSubnet'] = "10.0.{$k}.0/24";
                        break;
                    }
                }
                $wan = collect($data['interfaces'])->firstWhere('id', 'wan')['ipaddr'] ?? null;
                if ($wan && filter_var($wan, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $data['suggestedHost'] = $wan;
                }
            } catch (\Throwable $e) {
                $data['readError'] = $e->getMessage();
            }
        }
        return view('vpn.admin.site', $data);
    }

    public function setup(Request $request, Company $company, VpnSite $site)
    {
        $this->authorizeManage($request, $company);
        $site = $this->siteOf($company, $site);
        $v = $request->validate([
            'lan' => ['required', 'regex:/^[a-z0-9_]{1,20}$/i'],
            'wan' => ['required', 'regex:/^[a-z0-9_]{1,20}$/i'],
            'port' => ['required', 'integer', 'between:1024,65535'],
            'subnet' => ['required', 'string', 'max:20'],
            'endpoint_host' => ['required', 'regex:/^[A-Za-z0-9.-]{1,120}$/'],
        ]);
        try {
            WireGuard::parseSubnet($v['subnet']);
            $r = $this->vpn->driver($site)->setup(['listen_port' => (int) $v['port'], 'subnet' => $v['subnet'], 'lan' => $v['lan'], 'wan' => $v['wan']]);
        } catch (\Throwable $e) {
            $site->update(['status' => 'error', 'last_error' => $e->getMessage()]);
            return redirect()->route('vpn.site', [$company, $site])->with('error', 'Setup stopped: ' . $e->getMessage());
        }
        $site->update([
            'status' => 'ready', 'tunnel' => $r['ref'], 'tunnel_name' => $r['name'], 'server_public_key' => $r['public_key'],
            'subnet' => $v['subnet'], 'endpoint' => "{$v['endpoint_host']}:{$v['port']}", 'dns' => $r['gateway'] ?: WireGuard::firstHost($v['subnet']), 'last_error' => null,
        ]);
        VpnAuditLog::record($company->id, $this->actor($request), "wireguard_created {$site->firewall->name} {$r['name']} {$v['subnet']}");
        return redirect()->route('vpn.site', [$company, $site])->with('success', 'WireGuard is ready on this firewall.')->with('vpn_log', $r['log']);
    }

    public function adopt(Request $request, Company $company, VpnSite $site)
    {
        $this->authorizeManage($request, $company);
        $site = $this->siteOf($company, $site);
        $v = $request->validate([
            'tunnel' => ['required', 'string', 'max:64'],
            'subnet' => ['required', 'string', 'max:20'],
            'endpoint' => ['required', 'regex:/^[A-Za-z0-9.-]{1,120}:\d{2,5}$/'],
            'dns' => ['required', 'regex:/^[0-9., ]{7,100}$/'],
        ]);
        try {
            WireGuard::parseSubnet($v['subnet']);
            $t = collect($this->vpn->driver($site)->tunnels())->firstWhere('ref', $v['tunnel']);
            if (!$t || !WireGuard::isKey($t['public_key'])) {
                throw new VpnException('That tunnel wasn\'t found on the firewall.');
            }
        } catch (\Throwable $e) {
            return back()->with('error', 'Couldn\'t adopt: ' . $e->getMessage());
        }
        $site->update(['status' => 'ready', 'tunnel' => $t['ref'], 'tunnel_name' => $t['name'], 'server_public_key' => $t['public_key'], 'subnet' => $v['subnet'], 'endpoint' => $v['endpoint'], 'dns' => $v['dns'], 'last_error' => null]);
        VpnAuditLog::record($company->id, $this->actor($request), "wireguard_adopted {$site->firewall->name} {$t['name']} {$v['subnet']}");
        return redirect()->route('vpn.site', [$company, $site])->with('success', 'Tunnel adopted. People with VPN access can add devices now.');
    }

    public function settings(Request $request, Company $company, VpnSite $site)
    {
        $this->authorizeManage($request, $company);
        $site = $this->siteOf($company, $site);
        $v = $request->validate([
            'endpoint' => ['required', 'regex:/^[A-Za-z0-9.-]{1,120}:\d{2,5}$/'],
            'dns' => ['required', 'regex:/^[0-9., ]{7,100}$/'],
        ]);
        $site->update($v);
        VpnAuditLog::record($company->id, $this->actor($request), "site_settings {$site->firewall->name} {$v['endpoint']}");
        return back()->with('success', 'Saved. New devices use these settings.');
    }

    public function destroySite(Request $request, Company $company, VpnSite $site)
    {
        $this->authorizeManage($request, $company);
        $site = $this->siteOf($company, $site);
        if ($site->devices()->exists()) {
            return back()->with('error', 'Remove this site\'s devices first (or the people who own them).');
        }
        $name = $site->firewall->name;
        $site->delete();
        VpnAuditLog::record($company->id, $this->actor($request), "site_removed {$name}");
        return redirect()->route('vpn.company', $company)->with('success', "VPN turned off for {$name} in AdmixCentral. Nothing on the firewall was changed.");
    }
}

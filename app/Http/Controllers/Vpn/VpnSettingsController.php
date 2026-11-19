<?php

namespace App\Http\Controllers\Vpn;

use App\Http\Controllers\Controller;
use App\Models\Company;
use App\Models\Vpn\VpnCompany;
use App\Models\Vpn\VpnSite;
use App\Models\Vpn\VpnUser;
use App\Services\Vpn\Microsoft;
use App\Services\Vpn\VpnSettings;
use Illuminate\Http\Request;

/** Global admins: the Microsoft 365 app, the staff page host name, the device limit, and every company's VPN at a glance. */
class VpnSettingsController extends Controller
{
    public function index()
    {
        return view('vpn.admin.settings', [
            'clientId' => VpnSettings::clientId(),
            'hasSecret' => VpnSettings::hasClientSecret(),
            'portalHost' => VpnSettings::portalHost(),
            'maxDevices' => VpnSettings::maxDevices(),
            'redirects' => [VpnSettings::portalUrl('/vpn/callback'), VpnSettings::portalUrl('/vpn/consent/callback')],
            'companies' => Company::orderBy('name')->get()->map(fn ($c) => [
                'company' => $c,
                'tenant' => VpnCompany::where('company_id', $c->id)->value('ms_tenant_name') ?? (VpnCompany::where('company_id', $c->id)->value('ms_tenant_id') ? 'connected' : null),
                'sites' => VpnSite::where('company_id', $c->id)->where('status', 'ready')->count(),
                'people' => VpnUser::where('company_id', $c->id)->count(),
            ]),
        ]);
    }

    public function update(Request $request)
    {
        $v = $request->validate([
            'ms_client_id' => ['nullable', 'string', 'max:36'],
            'ms_client_secret' => ['nullable', 'string', 'max:200'],
            'portal_host' => ['nullable', 'regex:/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', 'max:120'],
            'max_devices' => ['required', 'integer', 'between:1,50'],
        ]);
        if (!empty($v['ms_client_id']) && !Microsoft::isGuid($v['ms_client_id'])) {
            return back()->withErrors(['ms_client_id' => 'The application (client) ID looks like 00000000-0000-0000-0000-000000000000.'])->withInput();
        }
        $host = strtolower((string) ($v['portal_host'] ?? ''));
        $adminHost = parse_url((string) config('app.url'), PHP_URL_HOST);
        if ($host !== '' && $adminHost && strcasecmp($host, $adminHost) === 0) {
            return back()->withErrors(['portal_host' => 'Use a separate name (e.g. wguard.cfbtel.com): only the VPN pages are served on it.'])->withInput();
        }
        VpnSettings::set('ms_client_id', strtolower((string) ($v['ms_client_id'] ?? '')));
        if (!empty($v['ms_client_secret'])) {
            VpnSettings::set('ms_client_secret', $v['ms_client_secret']); // blank keeps the saved secret
        }
        VpnSettings::set('portal_host', $host);
        VpnSettings::set('max_devices', (string) $v['max_devices']);
        return redirect()->route('vpn.settings')->with('success', 'VPN settings saved.');
    }
}

<?php

namespace App\Http\Controllers\Vpn;

use App\Http\Controllers\Controller;
use App\Models\Company;
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
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Log;

/**
 * The staff page (e.g. https://wguard.cfbtel.com/vpn): people a company admin gave VPN access sign in with
 * their own Microsoft 365 account and add or remove their devices. It never shows the AdmixCentral console.
 */
class PortalController extends Controller
{
    private const SESSION = 'vpn_portal';
    private const PENDING = 'vpn_portal_login';
    public const PLATFORMS = ['windows' => 'Windows PC', 'macos' => 'Mac', 'iphone' => 'iPhone / iPad', 'android' => 'Android'];

    public function __construct(private VpnManager $vpn, private \App\Services\Vpn\VpnAccounts $accounts, private \App\Services\Vpn\VpnAccess $access)
    {
    }


    /** The signed-in VPN person, re-read from the database (access may have been removed since). */
    private function person(Request $request): ?VpnUser
    {
        $s = $request->session()->get(self::SESSION);
        if (!is_array($s) || ($s['exp'] ?? 0) < time()) {
            return null;
        }
        $user = VpnUser::find($s['id'] ?? 0);
        if (!$user) {
            return null;
        }
        if ($user->isLocal()) {
            // A password change (or reset) signs out older sessions.
            return ($s['auth'] ?? '') === 'local' && $user->password && hash_equals($user->passwordVersion(), (string) ($s['pv'] ?? '')) ? $user : null;
        }
        return ($s['auth'] ?? 'microsoft') === 'microsoft' && $user->ms_oid === ($s['oid'] ?? null) ? $user : null;
    }

    private function startSession(Request $request, VpnUser $user, string $how)
    {
        $request->session()->regenerate();
        $request->session()->put(self::SESSION, [
            'id' => $user->id,
            'auth' => $user->isLocal() ? 'local' : 'microsoft',
            'oid' => $user->ms_oid,
            'pv' => $user->isLocal() ? $user->passwordVersion() : null,
            'exp' => time() + 30 * 60,
        ]);
        $user->update(['last_login_at' => now()]);
        VpnAuditLog::record($user->company_id, $user->upn, "signed_in ({$how})");
        return redirect('/vpn');
    }

    private function onPortalHost(Request $request): ?\Illuminate\Http\RedirectResponse
    {
        $host = VpnSettings::portalHost();
        if ($host && strcasecmp($request->getHost(), $host) !== 0 && $request->isMethod('GET')) {
            return redirect()->away(VpnSettings::portalUrl('/' . ltrim($request->path(), '/')));
        }
        return null;
    }

    private function message(string $title, string $text, int $status = 200, ?VpnUser $user = null)
    {
        return response()->view('vpn.portal.message', compact('title', 'text', 'user'), $status);
    }

    public function index(Request $request)
    {
        if ($r = $this->onPortalHost($request)) {
            return $r;
        }
        $user = $this->person($request);
        if (!$user) {
            return response()->view('vpn.portal.login', ['error' => session('vpn_error')]);
        }
        return $this->devicesPage($user);
    }

    private function devicesPage(VpnUser $user, ?array $notice = null, int $status = 200)
    {
        $sites = $this->access->sitesFor($user);
        $devices = $user->activeDevices()->with('site.firewall')->orderBy('created_at')->get();
        return response()->view('vpn.portal.devices', [
            'user' => $user,
            'company' => Company::find($user->company_id),
            'sites' => $sites,
            'devices' => $devices,
            'max' => VpnSettings::maxDevices(),
            'platforms' => self::PLATFORMS,
            'notice' => $notice,
        ], $status);
    }

    public function help()
    {
        return response()->view('vpn.portal.help', ['platforms' => self::PLATFORMS]);
    }

    /** Step 1: the work email picks the company (by its email domains) and so its Microsoft app. */
    public function login(Request $request)
    {
        if ($request->isMethod('GET')) {
            return redirect('/vpn');
        }
        $email = strtolower(trim((string) $request->input('email')));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return redirect('/vpn')->with('vpn_error', 'Enter your work email address.');
        }
        // People with an email-and-password VPN account get the password step instead of Microsoft.
        if (VpnUser::findLocalByEmail($email)) {
            return response()->view('vpn.portal.password', ['email' => $email, 'error' => null]);
        }
        $vc = VpnCompany::forEmail($email);
        $own = $vc && $vc->hasOwnApp() ? $vc : null;
        try {
            $login = Microsoft::for($own)->loginUrl(VpnSettings::portalUrl('/vpn/callback'), $email);
        } catch (VpnException $e) {
            return $this->message('Not available yet', 'Your organization isn\'t set up for CFBTEL VPN yet. Contact your IT admin or CFBTEL support.', 503);
        }
        $request->session()->put(self::PENDING, $login['pending'] + ['exp' => time() + 600, 'company' => $own?->id]);
        return redirect()->away($login['url']);
    }

    public function callback(Request $request)
    {
        $pending = $request->session()->pull(self::PENDING);
        if ($request->query('error')) {
            return redirect('/vpn')->with('vpn_error', strtok((string) $request->query('error_description', 'Microsoft sign-in was cancelled.'), "\r\n"));
        }
        if (!is_array($pending) || ($pending['exp'] ?? 0) < time() || !hash_equals((string) $pending['state'], (string) $request->query('state', ''))) {
            return redirect('/vpn')->with('vpn_error', 'Your sign-in expired. Please try again.');
        }
        // Redeem with the same app the sign-in started with (the company's own app, or CFBTEL's shared app).
        $own = !empty($pending['company']) ? VpnCompany::find($pending['company']) : null;
        try {
            $id = Microsoft::for($own)->redeem((string) $request->query('code', ''), VpnSettings::portalUrl('/vpn/callback'), $pending);
        } catch (\Throwable $e) {
            Log::warning('VPN portal: Microsoft sign-in failed', ['error' => $e->getMessage()]);
            return redirect('/vpn')->with('vpn_error', 'Microsoft sign-in failed. Please try again.');
        }
        $vc = $own ?? VpnCompany::where('ms_tenant_id', $id['tid'])->first();
        if ($vc && $vc->ms_tenant_id !== $id['tid']) {
            $vc = null; // signed in to another tenant than the company's own app
        }
        $user = $vc ? VpnUser::where('company_id', $vc->company_id)->where('auth_type', 'microsoft')->where('ms_oid', $id['oid'])->first() : null;

        // Microsoft 365 groups: members get access without being added by hand; people who came in
        // through a group lose it when they leave every group the company uses.
        if ($vc && \App\Services\Vpn\VpnAccess::usesGroups($vc) && (!$user || $user->viaGroup())) {
            $in = $this->access->membership($vc, $id['oid'], true);
            if ($in === null && !$user) {
                return $this->message('Try again shortly', 'Your company\'s Microsoft 365 groups couldn\'t be checked right now. Please try again in a few minutes.', 503);
            }
            if ($in !== null && !\App\Services\Vpn\VpnAccess::grantsAccess($vc, $in)) {
                if ($user) {
                    $this->vpn->removeUser($user, 'system (left the Microsoft 365 group)');
                    $user = null;
                }
            } elseif (!$user && $in !== null) {
                $user = VpnUser::create([
                    'company_id' => $vc->company_id, 'auth_type' => 'microsoft', 'source' => 'group', 'ms_oid' => $id['oid'],
                    'upn' => $id['upn'], 'name' => $id['name'], 'added_by' => 'Microsoft 365 group',
                ]);
                VpnAuditLog::record($vc->company_id, $id['upn'], 'vpn_access_given (Microsoft 365 group)');
            }
        }
        if (!$user) {
            Log::notice('VPN portal: sign-in refused', ['upn' => $id['upn'], 'tid' => $id['tid']]);
            return $this->message(
                'No VPN access',
                $vc ? 'You don\'t have VPN access yet. Ask your company\'s IT admin to add you.' : 'Your organization isn\'t set up for CFBTEL VPN. Contact CFBTEL support.',
                403,
            );
        }
        // Devices are labelled with the sign-in name; keep it current.
        $user->update(['upn' => $id['upn'], 'name' => $id['name']]);
        return $this->startSession($request, $user, 'Microsoft');
    }

    /** Email-and-password sign-in (accounts invited by email, for companies without Microsoft Entra). */
    public function passwordLogin(Request $request)
    {
        $email = \App\Services\Vpn\VpnAccounts::cleanEmail($request->input('email'));
        $password = (string) $request->input('password', '');
        if (!$email || $password === '') {
            return response()->view('vpn.portal.password', ['email' => (string) $email, 'error' => 'Enter your email and password.'], 422);
        }
        $r = $this->accounts->attempt($email, $password);
        if (!$r['user']) {
            return response()->view('vpn.portal.password', ['email' => $email, 'error' => $r['error']], 422);
        }
        return $this->startSession($request, $r['user'], 'password');
    }

    /** "Forgot password?": always the same answer, so it can't be used to find accounts. */
    public function forgot(Request $request)
    {
        $email = \App\Services\Vpn\VpnAccounts::cleanEmail($request->input('email'));
        $user = $email ? VpnUser::findLocalByEmail($email) : null;
        if ($user) {
            try {
                $this->accounts->sendLink($user, true);
                VpnAuditLog::record($user->company_id, $user->upn, 'password_reset_requested');
            } catch (\Throwable $e) {
                Log::error('VPN portal: sending a password link failed', ['error' => $e->getMessage()]);
            }
        }
        return $this->message('Check your email', 'If that address has a VPN account, we\'ve sent it a link to set a new password. The link works for one hour.');
    }

    /** The emailed invitation / new-password link. */
    public function passwordForm(Request $request, string $token)
    {
        $user = \App\Services\Vpn\VpnAccounts::userForToken($token);
        if (!$user) {
            return $this->message('Link expired', 'This link has expired or was already used. Use "Forgot password?" on the sign-in page, or ask your IT admin to resend your invitation.', 410);
        }
        return response()->view('vpn.portal.set-password', ['account' => $user, 'token' => $token, 'error' => null, 'min' => \App\Services\Vpn\VpnAccounts::MIN_PASSWORD]);
    }

    public function setPassword(Request $request, string $token)
    {
        $user = \App\Services\Vpn\VpnAccounts::userForToken($token);
        if (!$user) {
            return $this->message('Link expired', 'This link has expired or was already used. Use "Forgot password?" on the sign-in page.', 410);
        }
        $password = (string) $request->input('password', '');
        $min = \App\Services\Vpn\VpnAccounts::MIN_PASSWORD;
        $error = match (true) {
            mb_strlen($password) < $min => "Use at least {$min} characters.",
            mb_strlen($password) > 200 => 'That password is too long.',
            !hash_equals($password, (string) $request->input('password_confirmation', '')) => 'The two passwords don\'t match.',
            strcasecmp($password, $user->upn) === 0 => 'Don\'t use your email address as the password.',
            default => null,
        };
        if ($error) {
            return response()->view('vpn.portal.set-password', ['account' => $user, 'token' => $token, 'error' => $error, 'min' => $min], 422);
        }
        $this->accounts->setPassword($user, $password);
        return $this->startSession($request, $user->fresh(), 'new password');
    }

    public function logout(Request $request)
    {
        $request->session()->forget(self::SESSION);
        $request->session()->regenerate();
        return redirect('/vpn');
    }

    public function addDevice(Request $request)
    {
        $user = $this->person($request);
        if (!$user) {
            return redirect('/vpn')->with('vpn_error', 'Please sign in again.');
        }
        $name = WireGuard::cleanDeviceName($request->input('name'));
        $platform = array_key_exists($request->input('platform'), self::PLATFORMS) ? $request->input('platform') : 'windows';
        $site = VpnSite::with('firewall')->where('company_id', $user->company_id)->find((int) $request->input('site'));
        if (!$name) {
            return $this->devicesPage($user, ['error', 'Use 1–32 letters, numbers, spaces, dots, dashes or underscores.'], 422);
        }
        if (!$site || !$site->isReady()) {
            return $this->devicesPage($user, ['error', 'Pick a site.'], 422);
        }
        if (!$this->access->sitesFor($user, true)->contains('id', $site->id)) {
            return $this->devicesPage($user, ['error', "You don't have access to {$site->firewall->name}. Ask your IT admin to add you to its Microsoft 365 group."], 403);
        }
        try {
            $made = $this->vpn->addDevice($user, $site, $name);
        } catch (VpnException $e) {
            return $this->devicesPage($user, ['error', $e->getMessage()], 422);
        }
        $svg = (new Writer(new ImageRenderer(new RendererStyle(280, 1), new SvgImageBackEnd())))->writeString($made['config']);
        return response()->view('vpn.portal.new-device', [
            'user' => $user,
            'device' => $made['device'],
            'site' => $site,
            'platform' => $platform,
            'platforms' => self::PLATFORMS,
            'qrSvg' => $svg,
            // The configuration holds the private key: it goes to the browser once and is never stored.
            'downloadHref' => 'data:application/octet-stream;base64,' . base64_encode($made['config']),
            'fileName' => preg_replace('/[^A-Za-z0-9._-]+/', '-', "CFBTEL-{$site->firewall->name}-{$name}") . '.conf',
        ]);
    }

    public function removeDevice(Request $request, int $device)
    {
        $user = $this->person($request);
        if (!$user) {
            return redirect('/vpn')->with('vpn_error', 'Please sign in again.');
        }
        $d = VpnDevice::where('vpn_user_id', $user->id)->whereNull('revoked_at')->find($device);
        if (!$d) {
            return $this->devicesPage($user, ['error', 'Unknown device.'], 404);
        }
        try {
            $this->vpn->removeDevice($d, $user->upn);
            return $this->devicesPage($user, ['ok', "“{$d->name}” was removed. It can no longer connect."]);
        } catch (\Throwable $e) {
            Log::warning('VPN portal: removing a device failed', ['device' => $d->id, 'error' => $e->getMessage()]);
            return $this->devicesPage($user, ['ok', "“{$d->name}” was switched off. The firewall will drop it within 15 minutes."]);
        }
    }

    /** Microsoft sends a company's Global Administrator back here after approving the app. */
    public function consentCallback(Request $request)
    {
        try {
            $state = json_decode(Crypt::decryptString((string) $request->query('state', '')), true);
        } catch (\Throwable) {
            $state = null;
        }
        if (!is_array($state) || ($state['exp'] ?? 0) < time() || !($company = Company::find($state['c'] ?? 0))) {
            return $this->message('Link expired', 'This approval link has expired or is invalid. Ask CFBTEL for a new one.', 400);
        }
        $tenant = strtolower((string) $request->query('tenant', ''));
        if ($request->query('error') || $request->query('admin_consent') !== 'True' || !Microsoft::isGuid($tenant)) {
            return $this->message('Not approved', strtok((string) $request->query('error_description', 'The app wasn\'t approved.'), "\r\n"), 400);
        }
        $other = VpnCompany::where('ms_tenant_id', $tenant)->where('company_id', '!=', $company->id)->first();
        if ($other) {
            return $this->message('Already connected', 'This Microsoft 365 tenant is already linked to another company. Contact CFBTEL.', 409);
        }
        $vc = VpnCompany::forCompany($company);
        if ($vc->ms_tenant_id && $vc->ms_tenant_id !== $tenant) {
            return $this->message('Different tenant', 'This company is already linked to another Microsoft 365 tenant. Contact CFBTEL.', 409);
        }
        $vc->update(['ms_tenant_id' => $tenant, 'ms_tenant_name' => Microsoft::for(null)->tenantName($tenant)]);
        VpnAuditLog::record($company->id, 'microsoft-consent', "m365_connected {$tenant}");
        return $this->message('Microsoft 365 connected', "{$company->name} is connected to CFBTEL VPN. You can close this page.");
    }
}

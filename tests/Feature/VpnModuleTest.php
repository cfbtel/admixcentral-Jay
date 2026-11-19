<?php

namespace Tests\Feature;

use App\Models\Company;
use App\Models\Firewall;
use App\Models\User;
use App\Models\Vpn\VpnCompany;
use App\Models\Vpn\VpnDevice;
use App\Models\Vpn\VpnSite;
use App\Models\Vpn\VpnUser;
use App\Services\PfSenseApiService;
use App\Services\Vpn\Microsoft;
use App\Services\Vpn\MicrosoftSetup;
use App\Services\Vpn\PfSenseWireGuardDriver;
use App\Services\Vpn\VpnException;
use App\Services\Vpn\VpnManager;
use App\Services\Vpn\VpnSettings;
use App\Services\Vpn\WireGuard;
use App\Services\Vpn\WireGuardDriver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use phpseclib3\Crypt\RSA;
use Tests\TestCase;

/** In-memory firewall. */
class FakeWireGuard implements WireGuardDriver
{
    public array $tunnels = [];
    public array $peers = [];
    public array $setups = [];
    public bool $down = false;

    private function up(): void
    {
        if ($this->down) {
            throw new \RuntimeException('firewall unreachable');
        }
    }

    public function interfaces(): array
    {
        $this->up();
        return [
            ['id' => 'wan', 'descr' => 'WAN', 'ipaddr' => '45.23.212.130', 'subnet' => 28],
            ['id' => 'lan', 'descr' => 'LAN', 'ipaddr' => '192.168.1.1', 'subnet' => 24],
        ];
    }

    public function tunnels(): array
    {
        $this->up();
        return $this->tunnels;
    }

    public function setup(array $input): array
    {
        $this->up();
        $this->setups[] = $input;
        $t = ['ref' => 'tun_wg' . count($this->tunnels), 'name' => 'CFBTEL VPN', 'listen_port' => $input['listen_port'], 'public_key' => WireGuard::keyPair()['public']];
        $this->tunnels[] = $t;
        return ['ref' => $t['ref'], 'name' => $t['name'], 'public_key' => $t['public_key'], 'gateway' => WireGuard::firstHost($input['subnet']), 'log' => ['done']];
    }

    public function peers(string $tunnelRef): array
    {
        $this->up();
        return array_values(array_map(fn ($p) => ['public_key' => $p['public_key'], 'name' => $p['name'], 'addresses' => [$p['address']]], array_filter($this->peers, fn ($p) => $p['tunnel'] === $tunnelRef)));
    }

    public function addPeer(string $tunnelRef, array $peer): void
    {
        $this->up();
        $this->peers[] = $peer + ['tunnel' => $tunnelRef];
    }

    public function removePeers(string $tunnelRef, array $publicKeys): int
    {
        $this->up();
        $before = count($this->peers);
        $this->peers = array_values(array_filter($this->peers, fn ($p) => !($p['tunnel'] === $tunnelRef && in_array($p['public_key'], $publicKeys, true) && str_starts_with($p['name'], 'cfbvpn-'))));
        return $before - count($this->peers);
    }
}

/** Microsoft without the network. */
class FakeMicrosoft extends Microsoft
{
    public array $people = [];
    public bool $down = false;
    public array $calls = [];

    public function __construct(public string $label = 'shared')
    {
        parent::__construct('11111111-2222-3333-4444-555555555555', 'secret');
    }

    public function loginUrl(string $redirectUri, ?string $loginHint = null): array
    {
        $this->calls[] = "login {$loginHint}";
        return ['url' => "https://login.microsoftonline.com/{$this->label}?login_hint=" . urlencode((string) $loginHint), 'pending' => ['state' => 'st-' . bin2hex(random_bytes(4)), 'nonce' => 'n', 'verifier' => 'v']];
    }

    public function redeem(string $code, string $redirectUri, array $pending): array
    {
        $this->calls[] = "redeem {$code}";
        $p = $this->people[$code] ?? throw new VpnException('bad code');
        return ['tid' => $p['tid'], 'oid' => $p['oid'], 'upn' => $p['upn'], 'name' => $p['name']];
    }

    public function searchUsers(string $tenantId, string $query): array
    {
        if ($this->down) {
            throw new VpnException('graph down');
        }
        return array_values(array_map(fn ($p) => $this->asUser($p), array_filter($this->people, fn ($p) => $p['tid'] === $tenantId && empty($p['deleted']) && str_contains(strtolower($p['name']), strtolower($query)))));
    }

    public function userStatus(string $tenantId, string $oid): ?array
    {
        if ($this->down) {
            throw new VpnException('graph down');
        }
        foreach ($this->people as $p) {
            if ($p['tid'] === $tenantId && $p['oid'] === $oid && empty($p['deleted'])) {
                return $this->asUser($p);
            }
        }
        return null;
    }

    private function asUser(array $p): array
    {
        return ['oid' => $p['oid'], 'upn' => $p['upn'], 'name' => $p['name'], 'mail' => $p['upn'], 'enabled' => empty($p['disabled']), 'guest' => false];
    }

    public function tenantName(string $tenantId): ?string
    {
        return 'Acme Inc';
    }

    /** @var array<string, array{name: string, members: string[]}> group id => name and member oids */
    public array $groups = [];

    public function searchGroups(string $tenantId, string $query): array
    {
        return collect($this->groups)->filter(fn ($g) => str_contains(strtolower($g['name']), strtolower($query)))
            ->map(fn ($g, $id) => ['id' => $id, 'name' => $g['name'], 'description' => null, 'security' => true, 'm365' => false])->values()->all();
    }

    public function group(string $tenantId, string $groupId): ?array
    {
        $g = $this->groups[$groupId] ?? null;
        return $g ? ['id' => $groupId, 'name' => $g['name'], 'description' => null, 'security' => true, 'm365' => false] : null;
    }

    public function memberOf(string $tenantId, string $oid, array $groupIds): array
    {
        if ($this->down) {
            throw new VpnException('graph down');
        }
        $this->calls[] = "memberOf {$oid}";
        return array_values(array_filter($groupIds, fn ($id) => in_array($oid, $this->groups[$id]['members'] ?? [], true)));
    }
}

/** One-click setup without the network. */
class FakeSetup extends MicrosoftSetup
{
    public array $calls = [];
    public string $tid = '22222222-2222-2222-2222-222222222222';
    public int $n = 0;

    public function __construct()
    {
        parent::__construct('99999999-0000-0000-0000-000000000009', 'setup-secret');
    }

    public function authorizeUrl(?string $loginHint = null): array
    {
        return ['url' => 'https://login.microsoftonline.com/setup', 'pending' => ['state' => 'ss-' . bin2hex(random_bytes(4)), 'nonce' => 'n', 'verifier' => 'v']];
    }

    public function redeem(string $code, array $pending): array
    {
        $this->calls[] = "redeem {$code}";
        return ['tid' => $this->tid, 'upn' => 'admin@acme.com', 'name' => 'Acme Admin'];
    }

    public function organization(): array
    {
        return ['name' => 'Acme Inc', 'domains' => ['acme.com', 'acme.onmicrosoft.com']];
    }

    public function provision(string $redirectUri, ?string $existingAppId = null): array
    {
        $this->n++;
        $this->calls[] = 'provision ' . ($existingAppId ?? 'new') . " {$redirectUri}";
        return ['client_id' => 'dddddddd-0000-0000-0000-000000000001', 'client_secret' => "auto-secret-{$this->n}", 'object_id' => 'eeeeeeee-0000-0000-0000-000000000001',
            'key_id' => "ffffffff-0000-0000-0000-00000000000{$this->n}", 'expires_at' => \Carbon\CarbonImmutable::now()->addYears(2), 'reused' => $existingAppId !== null];
    }

    public function removeSecret(string $appObjectId, string $keyId): void
    {
        $this->calls[] = "remove-secret {$keyId}";
    }

    public function removeSetupAccess(): bool
    {
        $this->calls[] = 'cleanup';
        return true;
    }
}

class VpnModuleTest extends TestCase
{
    use RefreshDatabase;

    private const ACME_TID = '22222222-2222-2222-2222-222222222222';
    private const PORTAL = 'http://vpn.test';

    private const BETA_TID = '55555555-5555-5555-5555-555555555555';

    private FakeWireGuard $fw;
    private FakeMicrosoft $ms;
    private FakeMicrosoft $msOwn; // Beta's own app in Beta's own Entra

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.key' => 'base64:' . base64_encode(str_repeat('x', 32))]);
        $this->withoutVite();
        Http::preventStrayRequests();
        $this->fw = new FakeWireGuard();
        $this->ms = new FakeMicrosoft();
        $this->ms->people = [
            'ann' => ['tid' => self::ACME_TID, 'oid' => 'aaaaaaaa-0000-0000-0000-000000000001', 'upn' => 'ann@acme.com', 'name' => 'Ann'],
            'bob' => ['tid' => self::ACME_TID, 'oid' => 'aaaaaaaa-0000-0000-0000-000000000002', 'upn' => 'bob@acme.com', 'name' => 'Bob'],
            'carl' => ['tid' => self::ACME_TID, 'oid' => 'aaaaaaaa-0000-0000-0000-000000000003', 'upn' => 'carl@acme.com', 'name' => 'Carl'],
            'eve' => ['tid' => '44444444-4444-4444-4444-444444444444', 'oid' => 'eeeeeeee-0000-0000-0000-000000000001', 'upn' => 'eve@evil.com', 'name' => 'Eve'],
        ];
        $this->msOwn = new FakeMicrosoft('beta-own-app');
        $this->msOwn->people = [
            'bea' => ['tid' => self::BETA_TID, 'oid' => 'bbbbbbbb-0000-0000-0000-000000000001', 'upn' => 'bea@beta.com', 'name' => 'Bea'],
            'ann' => $this->ms->people['ann'], // someone from another tenant using Beta's app
        ];
        Microsoft::$factory = fn ($vc) => $vc && $vc->hasOwnApp() ? $this->msOwn : $this->ms;
        VpnManager::resolveDriversWith(fn () => $this->fw);
        VpnSettings::set('portal_host', 'vpn.test');
        VpnSettings::set('max_devices', '2');
    }

    protected function tearDown(): void
    {
        VpnManager::resolveDriversWith(null);
        Microsoft::$factory = null;
        MicrosoftSetup::$factory = null;
        MicrosoftSetup::$sleep = null;
        parent::tearDown();
    }

    /** Act in the AdmixCentral console (resets the root URL a staff-page request forced in this process). */
    private function console(User $user): static
    {
        \Illuminate\Support\Facades\URL::forceRootUrl(config('app.url'));
        return $this->actingAs($user);
    }

    /** CFBTEL global admin, Acme with one pfSense, its company admin and a read-only user. */
    private function world(): array
    {
        $acme = Company::create(['name' => 'Acme']);
        $beta = Company::create(['name' => 'Beta']);
        $global = User::create(['name' => 'Jay', 'email' => 'jay@cfbtel.com', 'password' => 'password', 'role' => 'admin', 'company_id' => null]);
        $acmeAdmin = User::create(['name' => 'Acme IT', 'email' => 'it@acme.test', 'password' => 'password', 'role' => 'admin', 'company_id' => $acme->id]);
        $acmeReader = User::create(['name' => 'Acme RO', 'email' => 'ro@acme.test', 'password' => 'password', 'role' => 'readonly', 'company_id' => $acme->id]);
        $betaAdmin = User::create(['name' => 'Beta IT', 'email' => 'it@beta.test', 'password' => 'password', 'role' => 'admin', 'company_id' => $beta->id]);
        foreach ([$global, $acmeAdmin, $acmeReader, $betaAdmin] as $u) {
            $u->forceFill(['email_verified_at' => now()])->save();
        }
        $firewall = Firewall::create(['name' => 'Acme HQ', 'company_id' => $acme->id, 'url' => 'https://fw.acme.test', 'os_type' => 'pfsense', 'auth_method' => 'basic', 'api_key' => 'u', 'api_secret' => 'p', 'netgate_id' => 'acme-hq']);
        return compact('acme', 'beta', 'global', 'acmeAdmin', 'acmeReader', 'betaAdmin', 'firewall');
    }

    /** Connect Acme's Microsoft 365 and build WireGuard on its firewall, as the global admin. */
    private function onboard(array $w): VpnSite
    {
        $page = $this->console($w['global'])->get("/companies/{$w['acme']->id}/vpn");
        $page->assertOk()->assertSee('Connect Microsoft 365');
        $state = Crypt::encryptString(json_encode(['c' => $w['acme']->id, 'exp' => time() + 600]));
        $this->get('/vpn/consent/callback?' . http_build_query(['tenant' => self::ACME_TID, 'admin_consent' => 'True', 'state' => $state]))->assertOk()->assertSee('Microsoft 365 connected');
        $this->console($w['global'])->post("/companies/{$w['acme']->id}/vpn/firewalls/{$w['firewall']->id}/enable")->assertRedirect();
        $site = VpnSite::firstOrFail();
        $this->console($w['global'])->get("/companies/{$w['acme']->id}/vpn/sites/{$site->id}")->assertOk()->assertSee('Create WireGuard')->assertSee('45.23.212.130', false);
        $this->console($w['global'])->post("/companies/{$w['acme']->id}/vpn/sites/{$site->id}/setup", ['lan' => 'lan', 'wan' => 'wan', 'port' => 51820, 'subnet' => '10.0.70.0/24', 'endpoint_host' => 'vpn.acme.com'])->assertRedirect();
        return $site->fresh();
    }

    private function grant(User $by, Company $company, string $who): void
    {
        $this->console($by)->post("/companies/{$company->id}/vpn/users", ['oid' => $this->ms->people[$who]['oid']])->assertRedirect();
    }

    /** Sign in on the staff page as a Microsoft 365 user (work email first, then Microsoft). */
    private function staffSignIn(string $who, ?string $email = null)
    {
        auth()->logout();
        $email ??= ($this->ms->people[$who] ?? $this->msOwn->people[$who])['upn'];
        $this->post(self::PORTAL . '/vpn/login', ['email' => $email])->assertRedirect();
        $state = session('vpn_portal_login')['state'];
        return $this->get(self::PORTAL . '/vpn/callback?' . http_build_query(['code' => $who, 'state' => $state]));
    }

    private function addDevice(string $name)
    {
        return $this->post(self::PORTAL . '/vpn/devices', ['site' => VpnSite::first()->id, 'name' => $name, 'platform' => 'iphone']);
    }

    public function test_portal_host_serves_only_the_vpn_pages(): void
    {
        $this->world();
        $this->get(self::PORTAL . '/')->assertRedirect('https://vpn.test/vpn');
        $this->get(self::PORTAL . '/vpn')->assertOk()->assertSee('Continue with Microsoft')->assertSee('Work email');
        $this->get(self::PORTAL . '/login')->assertNotFound();
        $this->get(self::PORTAL . '/dashboard')->assertNotFound();
        $this->get(self::PORTAL . '/vpn-admin/settings')->assertNotFound();
        $this->get(self::PORTAL . '/api/v1/firewalls')->assertNotFound();
        // On the console's own address the staff page sends people to the portal host.
        $this->get('http://localhost/vpn')->assertRedirect('https://vpn.test/vpn');
    }

    public function test_onboarding_builds_wireguard_and_links_the_tenant(): void
    {
        $w = $this->world();
        $site = $this->onboard($w);
        $this->assertSame(self::ACME_TID, VpnCompany::where('company_id', $w['acme']->id)->value('ms_tenant_id'));
        $this->assertTrue($site->isReady());
        $this->assertSame('vpn.acme.com:51820', $site->endpoint);
        $this->assertSame('10.0.70.1', $site->dns);
        $this->assertSame([['listen_port' => 51820, 'subnet' => '10.0.70.0/24', 'lan' => 'lan', 'wan' => 'wan']], $this->fw->setups);
    }

    public function test_company_admin_gives_access_and_the_person_adds_a_device(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->console($w['acmeAdmin'])->get("/companies/{$w['acme']->id}/vpn?q=bo&search=1")->assertOk()->assertSee('bob@acme.com');
        $this->grant($w['acmeAdmin'], $w['acme'], 'bob');
        $this->assertSame('bob@acme.com', VpnUser::first()->upn);

        $this->staffSignIn('bob')->assertRedirect('https://vpn.test/vpn');
        $this->get(self::PORTAL . '/vpn')->assertOk()->assertSee('Your devices');
        $res = $this->addDevice('Phone');
        $res->assertOk()->assertSee('<svg', false);
        $peer = $this->fw->peers[0];
        $device = VpnDevice::first();
        $this->assertSame('cfbvpn-' . $device->id, $peer['name']);
        $this->assertSame('10.0.70.2', $peer['address']);
        $this->assertTrue(WireGuard::isKey($peer['preshared_key']));
        preg_match('#data:application/octet-stream;base64,([A-Za-z0-9+/=]+)#', $res->getContent(), $m);
        $conf = base64_decode($m[1]);
        $this->assertStringContainsString('Endpoint = vpn.acme.com:51820', $conf);
        $this->assertStringContainsString('DNS = 10.0.70.1', $conf);
        $this->assertStringContainsString('Address = 10.0.70.2/32', $conf);
        $this->assertStringContainsString("PresharedKey = {$peer['preshared_key']}", $conf);
        $this->assertStringContainsString('PublicKey = ' . $this->fw->tunnels[0]['public_key'], $conf);
        $this->assertStringNotContainsString('PrivateKey', VpnDevice::first()->toJson());
    }

    public function test_people_nobody_assigned_and_unknown_tenants_are_refused(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->staffSignIn('carl')->assertForbidden()->assertSee('Ask your company');
        $this->staffSignIn('eve')->assertForbidden()->assertSee('isn&#039;t set up', false);
    }

    public function test_only_global_admins_and_the_companys_own_admins_manage_it(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->console($w['betaAdmin'])->get("/companies/{$w['acme']->id}/vpn")->assertForbidden();
        $this->console($w['betaAdmin'])->post("/companies/{$w['acme']->id}/vpn/users", ['oid' => $this->ms->people['bob']['oid']])->assertForbidden();
        $this->console($w['acmeReader'])->get("/companies/{$w['acme']->id}/vpn")->assertOk()->assertDontSee('Give VPN access');
        $this->console($w['acmeReader'])->post("/companies/{$w['acme']->id}/vpn/users", ['oid' => $this->ms->people['bob']['oid']])->assertForbidden();
        $this->console($w['acmeAdmin'])->get('/vpn-admin/settings')->assertStatus(403);
        // A person from another tenant can't be added by forging their id.
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users", ['oid' => $this->ms->people['eve']['oid']]);
        $this->assertSame(0, VpnUser::count());
    }

    public function test_removing_access_removes_devices_at_once_and_the_device_limit_holds(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->grant($w['acmeAdmin'], $w['acme'], 'bob');
        $this->staffSignIn('bob');
        $this->addDevice('One')->assertOk();
        $this->addDevice('Two')->assertOk();
        $this->addDevice('Three')->assertStatus(422)->assertSee('Remove one first');
        $this->assertCount(2, $this->fw->peers);

        $bob = VpnUser::first();
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/{$bob->id}/remove")->assertRedirect();
        $this->assertCount(0, $this->fw->peers);
        $this->assertSame(0, VpnDevice::count());
        auth()->logout();
        $this->addDevice('Again')->assertRedirect(); // signed out: access is gone
        $this->assertCount(0, $this->fw->peers);
    }

    public function test_a_person_removes_their_own_device(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->grant($w['global'], $w['acme'], 'bob');
        $this->staffSignIn('bob');
        $this->addDevice('Laptop');
        $d = VpnDevice::first();
        $this->post(self::PORTAL . "/vpn/devices/{$d->id}/remove")->assertOk()->assertSee('can no longer connect');
        $this->assertCount(0, $this->fw->peers);
    }

    public function test_sync_removes_devices_of_disabled_deleted_and_unknown_people_only(): void
    {
        $w = $this->world();
        $site = $this->onboard($w);
        foreach (['ann', 'bob', 'carl'] as $who) {
            $this->grant($w['global'], $w['acme'], $who);
            $this->staffSignIn($who);
            $this->addDevice('Phone')->assertOk();
        }
        $this->fw->peers[] = ['tunnel' => $site->tunnel, 'name' => 'Site-to-site', 'public_key' => WireGuard::keyPair()['public'], 'address' => '10.0.70.99'];
        $this->fw->peers[] = ['tunnel' => $site->tunnel, 'name' => 'cfbvpn-999', 'public_key' => WireGuard::keyPair()['public'], 'address' => '10.0.70.50'];
        $this->ms->people['bob']['disabled'] = true;
        $this->ms->people['carl']['deleted'] = true;

        $this->ms->down = true;
        $this->artisan('vpn:sync')->assertSuccessful();
        // Microsoft down: nobody loses access; only the peer AdmixCentral never created (cfbvpn-999) is cleaned up.
        $this->assertCount(3, VpnDevice::whereNull('revoked_at')->get());
        $this->assertEqualsCanonicalizing(['Site-to-site', ...VpnDevice::pluck('id')->map(fn ($i) => "cfbvpn-{$i}")->all()], collect($this->fw->peers)->pluck('name')->all());
        $this->ms->down = false;
        $this->artisan('vpn:sync')->assertSuccessful();

        $names = collect($this->fw->peers)->pluck('name')->all();
        $ann = VpnDevice::whereHas('user', fn ($q) => $q->where('upn', 'ann@acme.com'))->first();
        $this->assertEqualsCanonicalizing(['Site-to-site', 'cfbvpn-' . $ann->id], $names);
        $this->assertEqualsCanonicalizing(['ann@acme.com', 'bob@acme.com'], VpnUser::pluck('upn')->all());
    }

    public function test_when_the_firewall_is_down_removal_is_retried_by_the_sync(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->grant($w['global'], $w['acme'], 'bob');
        $this->staffSignIn('bob');
        $this->addDevice('Phone');
        $this->fw->down = true;
        $bob = VpnUser::first();
        $this->console($w['global'])->post("/companies/{$w['acme']->id}/vpn/users/{$bob->id}/remove")->assertRedirect()->assertSessionHas('warning');
        $this->assertNotNull(VpnDevice::first()->revoked_at);
        $this->fw->down = false;
        $this->artisan('vpn:sync')->assertSuccessful();
        $this->assertCount(0, $this->fw->peers);
        $this->assertSame(0, VpnDevice::count());
    }

    public function test_settings_page_saves_the_microsoft_app_with_an_encrypted_secret(): void
    {
        $w = $this->world();
        $this->console($w['global'])->post('/vpn-admin/settings', ['ms_client_id' => '11111111-2222-3333-4444-555555555555', 'ms_client_secret' => 's3cr3t-value', 'portal_host' => 'wguard.cfbtel.com', 'max_devices' => 5, 'proxy_ips' => '66.70.138.81'])->assertRedirect('/vpn-admin/settings');
        $this->assertSame(['66.70.138.81'], VpnSettings::proxyIps());
        $this->console($w['global'])->post('/vpn-admin/settings', ['portal_host' => 'wguard.cfbtel.com', 'max_devices' => 5, 'proxy_ips' => 'not-an-ip'])->assertSessionHasErrors('proxy_ips');
        $this->assertSame('s3cr3t-value', VpnSettings::clientSecret());
        $this->assertStringNotContainsString('s3cr3t', (string) \App\Models\SystemSetting::where('key', 'vpn_ms_client_secret')->value('value'));
        $this->assertSame('wguard.cfbtel.com', VpnSettings::portalHost());
        $this->console($w['global'])->get('/vpn-admin/settings')->assertOk()->assertSee('https://wguard.cfbtel.com/vpn/callback')->assertDontSee('s3cr3t-value');
    }

    public function test_microsoft_id_tokens_are_verified(): void
    {
        $key = RSA::createKey(2048);
        $jwk = json_decode($key->getPublicKey()->toString('JWK'), true)['keys'][0];
        Http::fake(['https://login.microsoftonline.com/common/discovery/v2.0/keys' => Http::response(['keys' => [$jwk + ['kid' => 'k1', 'use' => 'sig']]])]);
        $b64 = fn ($s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $sign = function (array $claims) use ($key, $b64) {
            $input = $b64(json_encode(['alg' => 'RS256', 'kid' => 'k1', 'typ' => 'JWT'])) . '.' . $b64(json_encode($claims));
            return $input . '.' . $b64($key->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256')->sign($input));
        };
        $app = '11111111-2222-3333-4444-555555555555';
        $ms = new Microsoft($app, 'secret');
        $ok = ['aud' => $app, 'iss' => 'https://login.microsoftonline.com/' . self::ACME_TID . '/v2.0', 'tid' => self::ACME_TID, 'oid' => 'AAAAAAAA-0000-0000-0000-000000000001', 'preferred_username' => 'Ann@Acme.com', 'name' => 'Ann', 'nonce' => 'n1', 'exp' => time() + 600, 'nbf' => time() - 5];

        $id = $ms->verifyIdToken($sign($ok), 'n1');
        $this->assertSame(['tid' => self::ACME_TID, 'oid' => 'aaaaaaaa-0000-0000-0000-000000000001', 'upn' => 'ann@acme.com', 'name' => 'Ann'], $id);

        foreach ([
            'wrong nonce' => [$ok, 'other'],
            'other tenant issuer' => [['iss' => 'https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444/v2.0'] + $ok, 'n1'],
            'other app' => [['aud' => 'ffffffff-ffff-ffff-ffff-ffffffffffff'] + $ok, 'n1'],
            'expired' => [['exp' => time() - 3600] + $ok, 'n1'],
        ] as $why => [$claims, $nonce]) {
            try {
                $ms->verifyIdToken($sign($claims), $nonce);
                $this->fail("accepted a token with {$why}");
            } catch (VpnException) {
                $this->addToAssertionCount(1);
            }
        }
        // Tampered payload: signature no longer matches.
        [$h, , $s] = explode('.', $sign($ok));
        $this->expectException(VpnException::class);
        $ms->verifyIdToken("{$h}." . $b64(json_encode(['oid' => 'x'] + $ok)) . ".{$s}", 'n1');
    }

    public function test_pfsense_driver_deletes_only_portal_peers_highest_id_first(): void
    {
        $fw = Firewall::create(['name' => 'Acme HQ', 'company_id' => Company::create(['name' => 'Acme'])->id, 'url' => 'https://fw.acme.test', 'os_type' => 'pfsense', 'auth_method' => 'basic', 'api_key' => 'u', 'api_secret' => 'p', 'netgate_id' => 'x1']);
        $k = [WireGuard::keyPair()['public'], WireGuard::keyPair()['public'], WireGuard::keyPair()['public']];
        Http::fake([
            'https://fw.acme.test/api/v2/vpn/wireguard/peers*' => Http::response(['data' => [
                ['id' => 0, 'tun' => 'tun_wg0', 'descr' => 'cfbvpn-1 ann@acme.com Phone', 'publickey' => $k[0], 'allowedips' => [['address' => '10.0.70.2', 'mask' => 32]]],
                ['id' => 1, 'tun' => 'tun_wg0', 'descr' => 'Site-to-site', 'publickey' => $k[1], 'allowedips' => [['address' => '10.0.70.99', 'mask' => 32]]],
                ['id' => 2, 'tun' => 'tun_wg0', 'descr' => 'cfbvpn-2 bob@acme.com Laptop', 'publickey' => $k[2], 'allowedips' => [['address' => '10.0.70.3', 'mask' => 32]]],
            ]]),
            'https://fw.acme.test/api/v2/vpn/wireguard/peer*' => Http::response(['data' => []]),
            'https://fw.acme.test/api/v2/vpn/wireguard/apply' => Http::response(['data' => []]),
        ]);
        $n = (new PfSenseWireGuardDriver(new PfSenseApiService($fw)))->removePeers('tun_wg0', $k);
        $this->assertSame(2, $n);
        $deletes = collect(Http::recorded())->map(fn ($r) => $r[0])->filter(fn ($r) => $r->method() === 'DELETE')->map(fn ($r) => $r->url())->values()->all();
        $this->assertSame(['https://fw.acme.test/api/v2/vpn/wireguard/peer?id=2', 'https://fw.acme.test/api/v2/vpn/wireguard/peer?id=0'], $deletes);
    }

    public function test_visitor_address_is_taken_from_the_trusted_proxy_only(): void
    {
        VpnSettings::set('proxy_ips', '66.70.138.81');
        $mk = fn (string $host, string $remote, string $xff) => \Illuminate\Http\Request::create("https://{$host}/vpn", 'GET', [], [], [], ['REMOTE_ADDR' => $remote, 'HTTP_X_FORWARDED_FOR' => $xff]);
        $this->assertSame('203.0.113.9', \App\Services\Vpn\ClientIp::of($mk('vpn.test', '66.70.138.81', '10.9.9.9, 203.0.113.9')));
        $this->assertSame('198.51.100.7', \App\Services\Vpn\ClientIp::of($mk('vpn.test', '198.51.100.7', '203.0.113.9')), 'not from the proxy: header ignored');
        $this->assertSame('66.70.138.81', \App\Services\Vpn\ClientIp::of($mk('localhost', '66.70.138.81', '203.0.113.9')), 'console host: header ignored');
        $this->assertSame('66.70.138.81', \App\Services\Vpn\ClientIp::of($mk('vpn.test', '66.70.138.81', 'garbage')));
    }

    public function test_opcache_reset_after_update_never_blocks_requests(): void
    {
        $this->world();
        @unlink(storage_path('framework/opcache-version'));
        $this->get(self::PORTAL . '/vpn')->assertOk();
        $this->get(self::PORTAL . '/vpn')->assertOk();
    }

    public function test_a_company_can_use_its_own_microsoft_app(): void
    {
        $w = $this->world();
        $page = $this->console($w['betaAdmin'])->get("/companies/{$w['beta']->id}/vpn")->assertOk()->assertSee('Enter the company');
        // Beta's admin enters Beta's own app registration and email domain.
        $this->console($w['betaAdmin'])->post("/companies/{$w['beta']->id}/vpn/microsoft", [
            'email_domains' => '@Beta.com, beta.us', 'ms_tenant_id' => self::BETA_TID,
            'ms_client_id' => 'cccccccc-0000-0000-0000-000000000001', 'ms_client_secret' => 'beta-secret',
        ])->assertRedirect()->assertSessionHas('success');
        $vc = VpnCompany::where('company_id', $w['beta']->id)->first();
        $this->assertTrue($vc->hasOwnApp());
        $this->assertSame(['beta.com', 'beta.us'], $vc->domains());
        $this->assertSame('beta-secret', $vc->ms_client_secret);
        $this->assertStringNotContainsString('beta-secret', (string) $vc->getRawOriginal('ms_client_secret'));

        // People are picked from Beta's tenant through Beta's app.
        $this->console($w['betaAdmin'])->post("/companies/{$w['beta']->id}/vpn/users", ['oid' => $this->msOwn->people['bea']['oid']])->assertRedirect();
        $this->assertSame('bea@beta.com', VpnUser::where('company_id', $w['beta']->id)->value('upn'));

        // Staff sign-in: the @beta.com email sends Bea through Beta's own app.
        $this->staffSignIn('bea', 'bea@beta.com')->assertRedirect('https://vpn.test/vpn');
        $this->assertSame(['login bea@beta.com', 'redeem bea'], $this->msOwn->calls);
        $this->assertSame([], array_values(array_filter($this->ms->calls, fn ($c) => str_contains($c, 'bea'))));

        // A token from another tenant through Beta's app is refused.
        $this->staffSignIn('ann', 'ann@beta.com')->assertForbidden();
    }

    public function test_email_domains_are_unique_and_unknown_domains_use_the_shared_app(): void
    {
        $w = $this->world();
        $this->console($w['global'])->post("/companies/{$w['acme']->id}/vpn/microsoft", ['email_domains' => 'acme.com'])->assertSessionHas('success');
        $this->console($w['global'])->post("/companies/{$w['beta']->id}/vpn/microsoft", ['email_domains' => 'ACME.com'])->assertSessionHasErrors('email_domains');
        $this->console($w['global'])->post("/companies/{$w['beta']->id}/vpn/microsoft", ['email_domains' => 'not a domain'])->assertSessionHasErrors('email_domains');
        $this->console($w['global'])->post("/companies/{$w['beta']->id}/vpn/microsoft", ['ms_client_id' => 'cccccccc-0000-0000-0000-000000000001'])->assertSessionHasErrors('ms_client_id');
        auth()->logout();
        $this->post(self::PORTAL . '/vpn/login', ['email' => 'someone@unknown.example'])->assertRedirect();
        $this->assertSame(['login someone@unknown.example'], $this->ms->calls);
        $this->post(self::PORTAL . '/vpn/login', ['email' => 'not-an-email'])->assertRedirect('https://vpn.test/vpn');
    }

    /** Messages captured by the "array" mailer (phpunit.xml sets MAIL_MAILER=array). */
    private function sentMail(): array
    {
        return collect(app('mail.manager')->mailer('array')->getSymfonyTransport()->messages())->map(fn ($m) => $m->getOriginalMessage())->all();
    }

    private function linkIn($message): string
    {
        preg_match('#https://vpn\.test(/vpn/password/[A-Za-z0-9_-]+)#', $message->getTextBody(), $m);
        return $m[1] ?? '';
    }

    public function test_invited_person_sets_a_password_signs_in_and_adds_a_device(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/invite", ['name' => 'Dan Doe', 'email' => 'Dan@NoMicrosoft.example'])->assertSessionHas('success');
        $dan = VpnUser::where('upn', 'dan@nomicrosoft.example')->firstOrFail();
        $this->assertTrue($dan->isLocal());
        $this->assertSame('invited', $dan->status());
        $mail = $this->sentMail();
        $this->assertCount(1, $mail);
        $this->assertSame('Your Acme VPN access', $mail[0]->getSubject());
        $link = $this->linkIn($mail[0]);
        $this->assertNotSame('', $link);
        $this->assertStringContainsString('Dan Doe', $mail[0]->getTextBody());

        auth()->logout();
        $this->get(self::PORTAL . $link)->assertOk()->assertSee('Set your VPN password');
        $this->post(self::PORTAL . $link, ['password' => 'short', 'password_confirmation' => 'short'])->assertStatus(422);
        $this->post(self::PORTAL . $link, ['password' => 'correct horse battery', 'password_confirmation' => 'different horse battery'])->assertStatus(422);
        $this->post(self::PORTAL . $link, ['password' => 'correct horse battery', 'password_confirmation' => 'correct horse battery'])->assertRedirect('https://vpn.test/vpn');
        $this->assertNotSame('correct horse battery', VpnUser::find($dan->id)->password);
        $this->get(self::PORTAL . $link)->assertStatus(410); // single use
        $this->addDevice('Laptop')->assertOk()->assertSee('<svg', false);
        $this->assertCount(1, $this->fw->peers);

        // Sign in again: email → password step (no Microsoft), wrong passwords lock the account.
        $this->post(self::PORTAL . '/vpn/logout');
        $this->post(self::PORTAL . '/vpn/login', ['email' => 'dan@nomicrosoft.example'])->assertOk()->assertSee('Forgot password?');
        $this->assertSame([], $this->ms->calls);
        $this->post(self::PORTAL . '/vpn/login/password', ['email' => 'dan@nomicrosoft.example', 'password' => 'correct horse battery'])->assertRedirect('https://vpn.test/vpn');
        $this->post(self::PORTAL . '/vpn/logout');
        for ($i = 0; $i < 5; $i++) {
            $this->post(self::PORTAL . '/vpn/login/password', ['email' => 'dan@nomicrosoft.example', 'password' => 'wrong password ' . $i])->assertStatus(422);
        }
        $this->assertSame('locked', VpnUser::find($dan->id)->status());
        $this->post(self::PORTAL . '/vpn/login/password', ['email' => 'dan@nomicrosoft.example', 'password' => 'correct horse battery'])->assertStatus(422)->assertSee('Too many wrong passwords');
        $this->post(self::PORTAL . '/vpn/login/password', ['email' => 'nobody@nomicrosoft.example', 'password' => 'whatever whatever'])->assertStatus(422)->assertSee('Wrong email or password');
    }

    public function test_admins_edit_resend_and_remove_email_accounts_and_password_reset_signs_out_old_sessions(): void
    {
        $w = $this->world();
        $this->onboard($w);
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/invite", ['name' => 'Dan', 'email' => 'dan@nomicrosoft.example']);
        $first = $this->linkIn($this->sentMail()[0]);
        $dan = VpnUser::where('upn', 'dan@nomicrosoft.example')->first();
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/{$dan->id}/resend")->assertSessionHas('success');
        $second = $this->linkIn($this->sentMail()[1]);
        auth()->logout();
        $this->get(self::PORTAL . $first)->assertStatus(410); // resend replaces the old link
        $this->post(self::PORTAL . $second, ['password' => 'first password 123', 'password_confirmation' => 'first password 123'])->assertRedirect();
        $this->get(self::PORTAL . '/vpn')->assertSee('Your devices');

        // Edit: new email; duplicates refused; other companies can't edit.
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/{$dan->id}/update", ['name' => 'Dan D', 'email' => 'dan.d@nomicrosoft.example'])->assertSessionHas('success');
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/invite", ['name' => 'Again', 'email' => 'dan.d@nomicrosoft.example'])->assertSessionHasErrors('invite');
        $this->console($w['betaAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/{$dan->id}/update", ['name' => 'X', 'email' => 'x@y.example'])->assertForbidden();
        $this->assertSame('dan.d@nomicrosoft.example', VpnUser::find($dan->id)->upn);

        // Forgot password: same answer for unknown emails; a reset signs out the old session.
        auth()->logout();
        $this->post(self::PORTAL . '/vpn/forgot', ['email' => 'unknown@nomicrosoft.example'])->assertOk()->assertSee('If that address has a VPN account');
        $this->assertCount(2, $this->sentMail());
        $this->post(self::PORTAL . '/vpn/forgot', ['email' => 'dan.d@nomicrosoft.example'])->assertOk();
        $reset = $this->sentMail()[2];
        $this->assertStringContainsString('Reset your Acme VPN password', $reset->getSubject());
        $this->post(self::PORTAL . $this->linkIn($reset), ['password' => 'second password 456', 'password_confirmation' => 'second password 456'])->assertRedirect();
        $this->addDevice('Phone')->assertOk();

        // Remove: devices go at once; sync leaves email accounts alone otherwise.
        $this->artisan('vpn:sync')->assertSuccessful();
        $this->assertCount(1, $this->fw->peers);
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/users/{$dan->id}/remove")->assertRedirect();
        $this->assertCount(0, $this->fw->peers);
        $this->assertNull(VpnUser::find($dan->id));
    }

    public function test_email_settings_require_the_link_and_send_a_test(): void
    {
        $w = $this->world();
        $base = ['smtp_encryption' => 'tls', 'invite_subject' => 'Hi', 'mail_from_address' => 'vpn@cfbtel.com'];
        $this->console($w['global'])->post('/vpn-admin/settings/email', $base + ['invite_body' => 'no link here'])->assertSessionHasErrors('invite_body');
        $this->console($w['global'])->post('/vpn-admin/settings/email', $base + ['invite_body' => 'Hello {name}: {link}', 'smtp_password' => 'mail-secret'])->assertSessionHas('success');
        $this->assertSame('mail-secret', VpnSettings::secret('smtp_password'));
        $this->assertStringNotContainsString('mail-secret', (string) \App\Models\SystemSetting::where('key', 'vpn_smtp_password')->value('value'));
        $this->console($w['global'])->post('/vpn-admin/settings/email/test')->assertSessionHas('success');
        $this->assertSame('CFBTEL VPN test email', $this->sentMail()[0]->getSubject());
        $this->console($w['acmeAdmin'])->post('/vpn-admin/settings/email', $base + ['invite_body' => '{link}'])->assertForbidden();
    }

    private function runSetup(string $link, string $code = 'c1')
    {
        auth()->logout();
        $this->get($link)->assertOk()->assertSee('Continue to Microsoft');
        $t = parse_url($link, PHP_URL_QUERY);
        parse_str($t, $q);
        $this->post(self::PORTAL . '/vpn/setup', ['t' => $q['t']])->assertRedirect('https://login.microsoftonline.com/setup');
        $state = session('vpn_ms_setup')['state'];
        return $this->get(self::PORTAL . '/vpn/setup/callback?' . http_build_query(['code' => $code, 'state' => $state]));
    }

    public function test_one_click_setup_creates_the_companys_own_app_and_saves_it(): void
    {
        $w = $this->world();
        // Without CFBTEL's setup app the button isn't offered.
        $this->console($w['acmeAdmin'])->get("/companies/{$w['acme']->id}/vpn")->assertOk()->assertDontSee('Connect Microsoft 365 automatically');

        $setup = new FakeSetup();
        MicrosoftSetup::$factory = fn () => $setup;
        $page = $this->console($w['acmeAdmin'])->get("/companies/{$w['acme']->id}/vpn")->assertOk()->assertSee('Connect Microsoft 365 automatically');
        $link = $page->viewData('setupLink');
        $this->assertStringStartsWith('https://vpn.test/vpn/setup?t=', $link);
        $this->console($w['acmeReader'])->get("/companies/{$w['acme']->id}/vpn")->assertOk()->assertDontSee('Connect Microsoft 365 automatically');

        $this->runSetup($link)->assertOk()->assertSee('Microsoft 365 connected')->assertSee('Acme Inc');
        $this->assertSame(['redeem c1', 'provision new https://vpn.test/vpn/callback', 'cleanup'], $setup->calls);
        $vc = VpnCompany::where('company_id', $w['acme']->id)->first();
        $this->assertSame(self::ACME_TID, $vc->ms_tenant_id);
        $this->assertSame('dddddddd-0000-0000-0000-000000000001', $vc->ms_client_id);
        $this->assertSame('auto-secret-1', $vc->ms_client_secret);
        $this->assertTrue($vc->hasOwnApp());
        $this->assertSame(['acme.com', 'acme.onmicrosoft.com'], $vc->domains());
        $this->assertTrue($vc->ms_secret_expires_at->isFuture());
        $this->assertNotNull($vc->ms_auto_setup_at);

        // The link works once.
        auth()->logout();
        $this->get($link)->assertStatus(400)->assertSee('Link expired');

        // Running it again reuses the app, gives it a new secret and removes the old one.
        $this->travel(2)->seconds();
        $again = $this->console($w['global'])->get("/companies/{$w['acme']->id}/vpn")->assertOk()->assertSee('Run automatic setup again')->viewData('setupLink');
        $setup->calls = [];
        $this->runSetup($again, 'c2')->assertOk()->assertSee('updated');
        $this->assertSame(['redeem c2', 'provision dddddddd-0000-0000-0000-000000000001 https://vpn.test/vpn/callback', 'remove-secret ffffffff-0000-0000-0000-000000000001', 'cleanup'], $setup->calls);
        $this->assertSame('auto-secret-2', $vc->fresh()->ms_client_secret);

        // The same tenant can't be linked to a second company, and domains stay unique.
        $this->travel(2)->seconds();
        $betaLink = $this->console($w['betaAdmin'])->get("/companies/{$w['beta']->id}/vpn")->assertOk()->viewData('setupLink');
        $this->runSetup($betaLink, 'c3')->assertStatus(409)->assertSee('already linked to another company');
        $this->assertNull(VpnCompany::where('company_id', $w['beta']->id)->value('ms_tenant_id'));

        // A forged or tampered link is refused.
        $this->get(self::PORTAL . '/vpn/setup?t=nope')->assertStatus(400);
    }

    public function test_setup_provisions_an_entra_app_through_microsoft_graph(): void
    {
        MicrosoftSetup::$sleep = fn (int $s) => null;
        $graph = '00000000-aaaa-0000-0000-000000000000';
        $addPasswordTries = 0;
        Http::fake(function ($req) use ($graph, &$addPasswordTries) {
            $m = $req->method();
            $u = urldecode($req->url());
            return match (true) {
                $m === 'GET' && str_contains($u, "servicePrincipals(appId='00000003-0000-0000-c000-000000000000')") => Http::response(['id' => $graph,
                    'oauth2PermissionScopes' => collect(['openid' => 's1', 'profile' => 's2', 'email' => 's3', 'User.Read' => 's4', 'Mail.Read' => 's9'])->map(fn ($id, $v) => ['id' => $id, 'value' => $v])->values()->all(),
                    'appRoles' => [['id' => 'r1', 'value' => 'User.Read.All', 'allowedMemberTypes' => ['Application']], ['id' => 'r2', 'value' => 'GroupMember.Read.All', 'allowedMemberTypes' => ['Application']], ['id' => 'r9', 'value' => 'Mail.Read', 'allowedMemberTypes' => ['Application']]]]),
                $m === 'POST' && str_ends_with($u, '/v1.0/applications') => Http::response(['id' => 'obj-1', 'appId' => 'app-1'], 201),
                $m === 'POST' && str_ends_with($u, '/applications/obj-1/addPassword') => ++$addPasswordTries < 2
                    ? Http::response(['error' => ['code' => 'Request_ResourceNotFound', 'message' => 'Resource does not exist']], 404)
                    : Http::response(['keyId' => 'KEY-1', 'secretText' => 'the-secret']),
                $m === 'GET' && str_contains($u, "servicePrincipals(appId='app-1')") => Http::response(['error' => ['code' => 'Request_ResourceNotFound']], 404),
                $m === 'POST' && str_ends_with($u, '/v1.0/servicePrincipals') => Http::response(['id' => 'sp-1'], 201),
                $m === 'GET' && str_contains($u, '/servicePrincipals/sp-1/appRoleAssignments') => Http::response(['value' => []]),
                $m === 'POST' && str_contains($u, "/servicePrincipals/{$graph}/appRoleAssignedTo") => Http::response(['id' => 'ra'], 201),
                $m === 'GET' && str_contains($u, '/oauth2PermissionGrants') => Http::response(['value' => []]),
                $m === 'POST' && str_ends_with($u, '/v1.0/oauth2PermissionGrants') => Http::response(['id' => 'g'], 201),
                default => Http::response(['error' => ['message' => "unexpected {$m} {$u}"]], 500),
            };
        });
        $app = (new MicrosoftSetup('setup-id', 'setup-secret'))->withToken('delegated')->provision('https://vpn.test/vpn/callback');
        $this->assertSame(['app-1', 'the-secret', 'obj-1', 'key-1', false], [$app['client_id'], $app['client_secret'], $app['object_id'], $app['key_id'], $app['reused']]);
        $this->assertEqualsWithDelta(now()->addYears(2)->getTimestamp(), $app['expires_at']->getTimestamp(), 5);
        $this->assertSame(2, $addPasswordTries);

        $sent = collect(Http::recorded())->map(fn ($r) => $r[0]);
        $create = $sent->first(fn ($r) => $r->method() === 'POST' && str_ends_with($r->url(), '/v1.0/applications'));
        $this->assertSame('AzureADMyOrg', $create['signInAudience']);
        $this->assertSame(['https://vpn.test/vpn/callback'], $create['web']['redirectUris']);
        $this->assertEqualsCanonicalizing(
            [['id' => 's1', 'type' => 'Scope'], ['id' => 's2', 'type' => 'Scope'], ['id' => 's3', 'type' => 'Scope'], ['id' => 's4', 'type' => 'Scope'], ['id' => 'r1', 'type' => 'Role'], ['id' => 'r2', 'type' => 'Role']],
            $create['requiredResourceAccess'][0]['resourceAccess']
        );
        $roles = $sent->filter(fn ($r) => str_contains($r->url(), 'appRoleAssignedTo'))->map(fn ($r) => $r->data())->values()->all();
        $this->assertSame([['principalId' => 'sp-1', 'resourceId' => $graph, 'appRoleId' => 'r1'], ['principalId' => 'sp-1', 'resourceId' => $graph, 'appRoleId' => 'r2']], $roles);
        $grant = $sent->first(fn ($r) => $r->method() === 'POST' && str_ends_with($r->url(), '/oauth2PermissionGrants'));
        $this->assertSame(['clientId' => 'sp-1', 'consentType' => 'AllPrincipals', 'resourceId' => $graph, 'scope' => 'openid profile email User.Read'], $grant->data());
        $this->assertTrue($sent->every(fn ($r) => $r->header('Authorization')[0] === 'Bearer delegated'));
    }

    public function test_settings_save_the_one_click_setup_app(): void
    {
        $w = $this->world();
        $this->console($w['global'])->get('/vpn-admin/settings')->assertOk()->assertSee('One-click Microsoft 365 setup')->assertSee('https://vpn.test/vpn/setup/callback');
        $this->console($w['global'])->post('/vpn-admin/settings/setup', ['setup_client_id' => 'bad'])->assertSessionHasErrors('setup_client_id');
        $this->console($w['global'])->post('/vpn-admin/settings/setup', ['setup_client_id' => '99999999-0000-0000-0000-000000000009', 'setup_client_secret' => 'shh'])->assertSessionHas('success');
        $this->assertTrue(MicrosoftSetup::make()->configured());
        $this->assertNotSame('shh', \App\Models\SystemSetting::where('key', 'vpn_setup_client_secret')->value('value'));
        $this->console($w['acmeAdmin'])->post('/vpn-admin/settings/setup', ['setup_client_id' => ''])->assertForbidden();
        $this->assertStringContainsString('https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize', MicrosoftSetup::make()->authorizeUrl()['url']);
        $this->assertStringContainsString('Application.ReadWrite.All', urldecode(MicrosoftSetup::make()->authorizeUrl()['url']));
    }

    public function test_setup_refuses_a_port_an_existing_tunnel_uses(): void
    {
        $w = $this->world();
        $this->fw->tunnels[] = ['ref' => 'tun_wg0', 'name' => 'Office', 'listen_port' => 51820, 'public_key' => WireGuard::keyPair()['public']];
        $this->console($w['global'])->post("/companies/{$w['acme']->id}/vpn/firewalls/{$w['firewall']->id}/enable")->assertRedirect();
        $site = VpnSite::firstOrFail();
        $this->console($w['global'])->post("/companies/{$w['acme']->id}/vpn/sites/{$site->id}/setup", ['lan' => 'lan', 'wan' => 'wan', 'port' => 51820, 'subnet' => '10.0.70.0/24', 'endpoint_host' => 'vpn.acme.com'])
            ->assertRedirect()->assertSessionHas('error', fn ($m) => str_contains($m, 'tun_wg0 (Office)') && str_contains($m, 'Adopt'));
        $this->assertSame([], $this->fw->setups);
        $this->assertNotSame('error', $site->fresh()->status);
    }

    private const G_VPN = '99999999-0000-0000-0000-00000000000a';
    private const G_SITE2 = '99999999-0000-0000-0000-00000000000b';

    /** Acme onboarded, plus a second ready firewall ("Acme Branch"). */
    private function twoSites(array $w): array
    {
        $site1 = $this->onboard($w);
        $fw2 = Firewall::create(['name' => 'Acme Branch', 'company_id' => $w['acme']->id, 'url' => 'https://fw2.acme.test', 'os_type' => 'pfsense', 'auth_method' => 'basic', 'api_key' => 'u', 'api_secret' => 'p', 'netgate_id' => 'acme-br']);
        $site2 = VpnSite::create(['company_id' => $w['acme']->id, 'firewall_id' => $fw2->id, 'status' => 'ready', 'tunnel' => 'tun_wg1', 'tunnel_name' => 'CFBTEL VPN',
            'server_public_key' => WireGuard::keyPair()['public'], 'subnet' => '10.0.71.0/24', 'endpoint' => 'branch.acme.com:51820', 'dns' => '10.0.71.1']);
        return [$site1, $site2];
    }

    public function test_a_company_group_gives_its_members_vpn_access(): void
    {
        $w = $this->world();
        $site = $this->onboard($w);
        $this->ms->groups = [self::G_VPN => ['name' => 'VPN', 'members' => [$this->ms->people['carl']['oid']]]];

        // The admin finds the group and uses it for the whole company.
        $page = $this->console($w['acmeAdmin'])->get("/companies/{$w['acme']->id}/vpn?gq=vp&groups=1")->assertOk()->assertSee('VPN')->assertSee('Whole company');
        $this->console($w['acmeReader'])->post("/companies/{$w['acme']->id}/vpn/groups/assign", ['group_id' => self::G_VPN, 'target' => 'company'])->assertForbidden();
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/groups/assign", ['group_id' => self::G_VPN, 'target' => 'company'])->assertSessionHas('success');
        $this->assertSame('VPN', VpnCompany::where('company_id', $w['acme']->id)->value('access_group_name'));

        // Carl isn't on the list but is in the group: he gets in and is added automatically.
        $this->staffSignIn('carl')->assertRedirect('https://vpn.test/vpn');
        $carl = VpnUser::where('ms_oid', $this->ms->people['carl']['oid'])->firstOrFail();
        $this->assertTrue($carl->viaGroup());
        $this->addDevice('Carl laptop')->assertOk();
        // Bob is in no group and not on the list.
        $this->staffSignIn('bob')->assertForbidden();

        // Carl leaves the group: the sync removes his access and his device.
        $this->ms->groups[self::G_VPN]['members'] = [];
        $this->artisan('vpn:sync')->assertSuccessful();
        $this->assertNull(VpnUser::find($carl->id));
        $this->assertSame([], $this->fw->peers);
        // …and signing in again is refused.
        $this->staffSignIn('carl')->assertForbidden();
    }

    public function test_a_firewall_group_limits_that_firewall_to_its_members(): void
    {
        $w = $this->world();
        [$site1, $site2] = $this->twoSites($w);
        $this->grant($w['global'], $w['acme'], 'ann');
        $this->grant($w['global'], $w['acme'], 'bob');
        $this->ms->groups = [self::G_SITE2 => ['name' => 'Branch VPN', 'members' => [$this->ms->people['ann']['oid'], $this->ms->people['carl']['oid']]]];
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/groups/assign", ['group_id' => self::G_SITE2, 'target' => (string) $site2->id])->assertSessionHas('success');
        $this->console($w['acmeAdmin'])->get("/companies/{$w['acme']->id}/vpn")->assertOk()->assertSee('members of <strong>Branch VPN</strong>', false);

        // Bob (not in the group) only sees the main firewall and can't add a device on the branch.
        $this->staffSignIn('bob')->assertRedirect();
        $this->get(self::PORTAL . '/vpn')->assertOk()->assertDontSee('Acme Branch');
        $this->post(self::PORTAL . '/vpn/devices', ['site' => $site2->id, 'name' => 'Bob phone', 'platform' => 'iphone'])->assertForbidden();
        $this->post(self::PORTAL . '/vpn/devices', ['site' => $site1->id, 'name' => 'Bob phone', 'platform' => 'iphone'])->assertOk();

        // Ann (in the group) can use both.
        $this->staffSignIn('ann')->assertRedirect();
        $this->get(self::PORTAL . '/vpn')->assertOk()->assertSee('Acme Branch');
        $this->post(self::PORTAL . '/vpn/devices', ['site' => $site2->id, 'name' => 'Ann laptop', 'platform' => 'windows'])->assertOk();

        // Carl isn't on the list but the branch group gives him access to the branch only.
        $this->staffSignIn('carl')->assertRedirect();
        $this->get(self::PORTAL . '/vpn')->assertOk()->assertSee('Acme Branch');
        $this->post(self::PORTAL . '/vpn/devices', ['site' => $site1->id, 'name' => 'Carl phone', 'platform' => 'iphone'])->assertOk(); // main has no group: open to everyone with access

        // Microsoft down: the sync removes nothing.
        $this->ms->down = true;
        $this->ms->groups[self::G_SITE2]['members'] = [];
        $this->artisan('vpn:sync')->assertSuccessful();
        $this->assertSame(1, VpnDevice::where('vpn_site_id', $site2->id)->whereNull('revoked_at')->count());

        // Ann leaves the group: her branch device goes, she keeps access (added by hand); Carl loses access.
        $this->ms->down = false;
        $this->artisan('vpn:sync')->assertSuccessful();
        $this->assertSame(0, VpnDevice::where('vpn_site_id', $site2->id)->whereNull('revoked_at')->count());
        $this->assertNotNull(VpnUser::where('upn', 'ann@acme.com')->first());
        $this->assertNull(VpnUser::where('upn', 'carl@acme.com')->first());
        $this->assertSame(['tun_wg0'], array_values(array_unique(array_column($this->fw->peers, 'tunnel'))));

        // Removing the group opens the branch to everyone with access again.
        $this->console($w['acmeAdmin'])->post("/companies/{$w['acme']->id}/vpn/groups/clear", ['target' => (string) $site2->id])->assertSessionHas('success');
        $this->assertNull($site2->fresh()->access_group_id);
    }

    public function test_pfsense_driver_installs_the_wireguard_package_when_missing(): void
    {
        $fw = Firewall::create(['name' => 'Acme HQ', 'company_id' => Company::create(['name' => 'Acme'])->id, 'url' => 'https://fw.acme.test', 'os_type' => 'pfsense', 'auth_method' => 'basic', 'api_key' => 'u', 'api_secret' => 'p', 'netgate_id' => 'x1']);
        $missing = ['code' => 424, 'status' => 'failed dependency', 'message' => "The requested action requires the 'pfSense-pkg-WireGuard' package but it is not installed."];
        Http::fake([
            'https://fw.acme.test/api/v2/vpn/wireguard/settings*' => Http::sequence()->push($missing, 424)->push(['data' => ['enable' => false]]),
            'https://fw.acme.test/api/v2/vpn/wireguard/tunnels*' => Http::response($missing, 424),
            'https://fw.acme.test/api/v2/system/package' => Http::response(['data' => ['name' => 'pfSense-pkg-WireGuard']]),
        ]);
        $driver = new PfSenseWireGuardDriver(new PfSenseApiService($fw));
        $this->assertSame([], $driver->tunnels());
        $this->assertTrue($driver->ensurePackage());
        $install = collect(Http::recorded())->map(fn ($r) => $r[0])->first(fn ($r) => $r->method() === 'POST');
        $this->assertSame('https://fw.acme.test/api/v2/system/package', $install->url());
        $this->assertSame(['name' => 'pfSense-pkg-WireGuard'], $install->data());
    }

    public function test_wireguard_helpers(): void
    {
        $kp = WireGuard::keyPair();
        $this->assertTrue(WireGuard::isKey($kp['public']) && WireGuard::isKey($kp['private']));
        $this->assertSame(base64_encode(sodium_crypto_scalarmult_base(base64_decode($kp['private']))), $kp['public']);
        $this->assertSame('10.0.70.1', WireGuard::firstHost('10.0.70.0/24'));
        $this->assertSame('10.0.70.3', WireGuard::allocate('10.0.70.0/24', ['10.0.70.2/32', '10.0.70.1']));
        $this->assertNull(WireGuard::allocate('10.0.70.0/29', ['10.0.70.2', '10.0.70.3', '10.0.70.4', '10.0.70.5', '10.0.70.6']));
        $this->assertNull(WireGuard::cleanDeviceName('a:b'));
        $this->assertSame('Work laptop', WireGuard::cleanDeviceName(' Work laptop '));
        $this->expectException(\InvalidArgumentException::class);
        WireGuard::parseSubnet('10.0.70.0/8');
    }
}

<?php

namespace App\Services\Vpn;

use App\Models\Vpn\VpnCompany;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/**
 * Microsoft 365 (Entra ID) for the VPN module, with one multi-tenant app registration owned by CFBTEL.
 *
 * - Staff sign-in: OpenID Connect authorization code flow with PKCE and nonce on /organizations;
 *   the ID token is verified against Microsoft's signing keys, and its issuer must match its own tenant.
 * - Each company approves the app once (admin consent), which lets AdmixCentral read that tenant's
 *   users (User.Read.All, application) so company admins can pick people and disabled accounts lose access.
 */
class Microsoft
{
    public const AUTHORITY = 'https://login.microsoftonline.com';
    public const GRAPH = 'https://graph.microsoft.com';
    private const GUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    /** Tests swap in a fake. @var (\Closure(?VpnCompany): Microsoft)|null */
    public static ?\Closure $factory = null;

    /**
     * @param string|null $tenant set for a company's own (single-tenant) app: sign-in goes to that tenant only;
     *                            null for CFBTEL's shared multi-tenant app (/organizations).
     */
    public function __construct(
        private ?string $clientId = null,
        private ?string $clientSecret = null,
        private ?string $tenant = null,
    ) {
        if ($this->clientId === null && $this->clientSecret === null && $this->tenant === null) {
            $this->clientId = VpnSettings::clientId();
            $this->clientSecret = VpnSettings::clientSecret();
        }
    }

    /** The Microsoft app to use for a company: its own app when it has one, otherwise CFBTEL's shared app. */
    public static function for(?VpnCompany $vc): self
    {
        if (self::$factory) {
            return (self::$factory)($vc);
        }
        if ($vc && $vc->hasOwnApp()) {
            return new self($vc->ms_client_id, $vc->ms_client_secret, $vc->ms_tenant_id);
        }
        return new self();
    }

    public function usesOwnApp(): bool
    {
        return $this->tenant !== null;
    }

    private function authorityPath(): string
    {
        return $this->tenant ? rawurlencode($this->tenant) : 'organizations';
    }

    public static function isGuid(?string $v): bool
    {
        return is_string($v) && preg_match(self::GUID, $v) === 1;
    }

    private static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function unb64u(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
    }

    private function requireApp(): void
    {
        if (!$this->clientId || !$this->clientSecret) {
            throw new VpnException('Microsoft 365 sign-in isn\'t configured yet (VPN settings: application ID and secret).');
        }
    }

    /** @return array{url: string, pending: array{state: string, nonce: string, verifier: string}} */
    public function loginUrl(string $redirectUri, ?string $loginHint = null): array
    {
        $this->requireApp();
        $pending = ['state' => self::b64u(random_bytes(18)), 'nonce' => self::b64u(random_bytes(18)), 'verifier' => self::b64u(random_bytes(32))];
        $query = http_build_query([
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $redirectUri,
            'response_mode' => 'query',
            'scope' => 'openid profile email',
            'state' => $pending['state'],
            'nonce' => $pending['nonce'],
            'code_challenge' => self::b64u(hash('sha256', $pending['verifier'], true)),
            'code_challenge_method' => 'S256',
        ] + ($loginHint ? ['login_hint' => $loginHint] : ['prompt' => 'select_account']));
        return ['url' => self::AUTHORITY . "/{$this->authorityPath()}/oauth2/v2.0/authorize?{$query}", 'pending' => $pending];
    }

    /** Exchange the code and return the verified identity. @return array{tid: string, oid: string, upn: string, name: string} */
    public function redeem(string $code, string $redirectUri, array $pending): array
    {
        $this->requireApp();
        $res = Http::asForm()->timeout(20)->post(self::AUTHORITY . "/{$this->authorityPath()}/oauth2/v2.0/token", [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $pending['verifier'],
            'scope' => 'openid profile email',
        ]);
        $idToken = $res->json('id_token');
        if (!$res->successful() || !is_string($idToken)) {
            throw new VpnException(strtok((string) ($res->json('error_description') ?? 'Microsoft sign-in failed.'), "\r\n"));
        }
        return $this->verifyIdToken($idToken, $pending['nonce']);
    }

    /** Verify signature (RS256, Microsoft's keys), audience, lifetime, tenant-bound issuer and nonce. */
    public function verifyIdToken(string $jwt, string $nonce): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new VpnException('Invalid sign-in token.');
        }
        [$h, $p, $s] = $parts;
        $header = json_decode(self::unb64u($h), true);
        $claims = json_decode(self::unb64u($p), true);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? '') !== 'RS256' || empty($header['kid'])) {
            throw new VpnException('Invalid sign-in token.');
        }
        $jwk = $this->signingKey((string) $header['kid']);
        $key = PublicKeyLoader::load(json_encode(['kty' => 'RSA', 'n' => $jwk['n'], 'e' => $jwk['e']]));
        if (!$key instanceof RSA\PublicKey || !$key->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256')->verify("{$h}.{$p}", self::unb64u($s))) {
            throw new VpnException('The sign-in token signature is invalid.');
        }
        $now = time();
        $tid = strtolower((string) ($claims['tid'] ?? ''));
        if (($claims['aud'] ?? null) !== $this->clientId) {
            throw new VpnException('The sign-in token is for another application.');
        }
        if (!is_numeric($claims['exp'] ?? null) || $claims['exp'] < $now - 300 || (is_numeric($claims['nbf'] ?? null) && $claims['nbf'] > $now + 300)) {
            throw new VpnException('The sign-in token has expired.');
        }
        if (!self::isGuid($tid) || ($claims['iss'] ?? '') !== self::AUTHORITY . "/{$tid}/v2.0") {
            throw new VpnException('The sign-in token\'s issuer doesn\'t match its tenant.');
        }
        if ($this->tenant && $tid !== strtolower($this->tenant)) {
            throw new VpnException('The sign-in token is from another tenant than this app\'s.');
        }
        if (!hash_equals($nonce, (string) ($claims['nonce'] ?? ''))) {
            throw new VpnException('The sign-in token doesn\'t belong to this sign-in.');
        }
        $oid = (string) ($claims['oid'] ?? '');
        $upn = strtolower((string) ($claims['preferred_username'] ?? $claims['email'] ?? ''));
        if (!self::isGuid($oid) || $upn === '') {
            throw new VpnException('The sign-in token has no user.');
        }
        return ['tid' => $tid, 'oid' => strtolower($oid), 'upn' => $upn, 'name' => (string) ($claims['name'] ?? $upn)];
    }

    private function signingKey(string $kid): array
    {
        $find = fn (array $keys) => collect($keys)->first(fn ($k) => ($k['kid'] ?? null) === $kid && ($k['kty'] ?? '') === 'RSA');
        $keys = Cache::get('vpn_ms_jwks', []);
        if (!$hit = $find($keys)) {
            $res = Http::timeout(15)->get(self::AUTHORITY . '/common/discovery/v2.0/keys');
            $keys = $res->json('keys') ?? [];
            if ($keys) {
                Cache::put('vpn_ms_jwks', $keys, now()->addHours(12));
            }
            $hit = $find($keys);
        }
        if (!$hit) {
            throw new VpnException('Microsoft signing key not found.');
        }
        return $hit;
    }

    public function adminConsentUrl(string $redirectUri, string $state): string
    {
        $this->requireApp();
        return self::AUTHORITY . '/organizations/v2.0/adminconsent?' . http_build_query([
            'client_id' => $this->clientId,
            'scope' => self::GRAPH . '/.default',
            'redirect_uri' => $redirectUri,
            'state' => $state,
        ]);
    }

    private function appToken(string $tenantId): string
    {
        $this->requireApp();
        $cacheKey = 'vpn_ms_token:' . sha1($this->clientId . '|' . $tenantId);
        if ($token = Cache::get($cacheKey)) {
            return $token;
        }
        $res = Http::asForm()->timeout(20)->post(self::AUTHORITY . '/' . rawurlencode($tenantId) . '/oauth2/v2.0/token', [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'client_credentials',
            'scope' => self::GRAPH . '/.default',
        ]);
        $token = $res->json('access_token');
        if (!$res->successful() || !is_string($token)) {
            $desc = (string) $res->json('error_description', '');
            $notApproved = $res->json('error') === 'invalid_client' || preg_match('/AADSTS(65001|700016|7000229)/', $desc);
            throw new VpnException($notApproved ? 'This company hasn\'t approved the CFBTEL VPN app in Microsoft 365 yet.' : (strtok($desc, "\r\n") ?: 'Microsoft token request failed.'));
        }
        Cache::put($cacheKey, $token, now()->addSeconds(max(60, (int) $res->json('expires_in', 3600) - 120)));
        return $token;
    }

    /** @return array<string, mixed>|null null on 404 */
    private function graph(string $tenantId, string $path, array $headers = []): ?array
    {
        $res = Http::withToken($this->appToken($tenantId))->withHeaders($headers)->acceptJson()->timeout(20)->get(self::GRAPH . '/v1.0' . $path);
        if ($res->status() === 404) {
            return null;
        }
        if (!$res->successful()) {
            throw new VpnException((string) $res->json('error.message', "Microsoft Graph error {$res->status()}"));
        }
        return $res->json();
    }

    private static function toUser(array $u): array
    {
        return [
            'oid' => strtolower((string) ($u['id'] ?? '')),
            'upn' => strtolower((string) ($u['userPrincipalName'] ?? '')),
            'name' => (string) ($u['displayName'] ?? $u['userPrincipalName'] ?? ''),
            'mail' => is_string($u['mail'] ?? null) ? $u['mail'] : null,
            'enabled' => ($u['accountEnabled'] ?? true) !== false,
            'guest' => ($u['userType'] ?? '') === 'Guest',
        ];
    }

    private const SELECT = '$select=id,displayName,userPrincipalName,mail,accountEnabled,userType';

    /** People in a company's tenant, for its admin to pick from. */
    public function searchUsers(string $tenantId, string $query): array
    {
        $q = trim(str_replace(['"', '\\'], '', $query));
        $path = $q !== ''
            ? '/users?$search=' . rawurlencode("\"displayName:{$q}\" OR \"mail:{$q}\"") . '&' . self::SELECT . '&$top=25&$orderby=displayName'
            : '/users?' . self::SELECT . '&$top=25&$orderby=displayName';
        return array_map([self::class, 'toUser'], $this->graph($tenantId, $path, ['ConsistencyLevel' => 'eventual'])['value'] ?? []);
    }

    /** Current state of one person; null when the account no longer exists. */
    public function userStatus(string $tenantId, string $oid): ?array
    {
        $u = $this->graph($tenantId, '/users/' . rawurlencode($oid) . '?' . self::SELECT);
        return $u === null ? null : self::toUser($u);
    }

    public function tenantName(string $tenantId): ?string
    {
        try {
            return $this->graph($tenantId, '/organization?$select=displayName')['value'][0]['displayName'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }
}

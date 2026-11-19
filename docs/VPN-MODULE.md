# VPN Access (WireGuard + Microsoft 365)

Self-service WireGuard remote access for each company managed in AdmixCentral.

**Who does what:**
* **Global admins (CFBTEL):**
  * set up the Microsoft app once;
  * connect each company's Microsoft 365;
  * turn on VPN for a company firewall. AdmixCentral then builds WireGuard on it through the API connection it
    already has.
* **Company admins** (AdmixCentral users with the *admin* role in that company) choose who gets VPN access, picking
  people from their own Microsoft 365.
* **Those people** sign in on the **staff VPN page** (e.g. `https://wguard.cfbtel.com/vpn`) with their Microsoft 365
  account. They add a device and get a QR code or `.conf` file for the free WireGuard or AmneziaVPN app. They never
  see the AdmixCentral console.
* **Losing access:** removing someone's access removes their devices at once. Every 15 minutes (`vpn:sync`) devices of
  disabled or deleted Microsoft 365 accounts are removed too.

Supported firewalls: **pfSense** (REST API package v2) and **OPNsense** (24.x or later, core WireGuard and Firewall →
Automation).

## 1. Microsoft 365 per company

Each company signs in with **its own** Microsoft 365. There are two ways to connect it, chosen per company on its
VPN page:

* **CFBTEL's shared app (default):** a Global Administrator of the company approves CFBTEL's multi-tenant app once
  (*Approve CFBTEL's app*, or send the link). Only that tenant's accounts can then sign in for the company.
* **The company's own app (optional):** create an app registration in **the company's own** Entra and enter its
  Directory (tenant) ID, Application (client) ID and client secret on the company's VPN page. The secret is
  encrypted.
  * Account type: *this organizational directory only*.
  * Redirect URI (Web): `https://<portal host>/vpn/callback`.
  * Graph permissions: delegated `openid`, `profile`, `email`, `User.Read`; application `User.Read.All` → **Grant
    admin consent**.
  * The company's staff sign-in, people search and access checks then use only that app. Renew the secret on the
    VPN page before it expires.

**Work email domains:** list each company's email domains (e.g. `acme.com`) on its VPN page.
- The staff page asks for the work email first, and its domain picks the company and its app. Microsoft then opens
  with that email filled in.
- Domains are required for companies with their own app, and must be unique across companies.
- Unknown domains use CFBTEL's shared app.

## 1a. CFBTEL's shared Microsoft app (once, in CFBTEL's Microsoft Entra; optional if every company uses its own)

Entra admin center → **App registrations → New registration**:
- Name **CFBTEL VPN**.
- Supported account types: **Accounts in any organizational directory (Multitenant)**.
- Redirect URIs (Web):
  - `https://<portal host>/vpn/callback`
  - `https://<portal host>/vpn/consent/callback`
- **API permissions → Microsoft Graph:**
  - delegated: `openid`, `profile`, `email`, `User.Read`;
  - application: `User.Read.All`;
  - then **Grant admin consent**.
- **Certificates & secrets → New client secret.** Copy the *Value*.

In AdmixCentral, open **VPN Access** in the sidebar (global admins). Enter:
- the application (client) ID;
- the secret (stored encrypted with the app key);
- the portal host name;
- the device limit per person.

## 2. Staff page host name

Only `/vpn` pages and `/vpn-assets` are served on the portal host. The console, its login and the API answer 404
there, and the session cookie is bound to that host.

Point the name at this server, either way:
- with a DNS record and a TLS certificate, or
- through a reverse proxy that keeps the `Host` header.

## 3. Onboarding a company

1. **Companies → company → VPN Access.**
2. **Microsoft 365:**
   - Either click **Approve CFBTEL's app** (or send the link, valid 7 days, to the company's Global Administrator),
     or enter the company's own app.
   - Enter the company's work email domains.
3. **Firewalls → Enable VPN → Create WireGuard.**
   - Choose the LAN users may reach, the WAN, the UDP port, the VPN network and the public name or IP.
   - AdmixCentral creates:
     - the tunnel;
     - rules on the VPN interface: DNS to the firewall, block the firewall's admin pages, allow the chosen LAN, block
       other private networks, internet (full tunnel);
     - the WAN rule;
     - on OPNsense, an outbound NAT rule.
   - On pfSense, outbound NAT must be Automatic or Hybrid.
   - For a firewall already set up by hand, use **Adopt an existing tunnel** instead.
4. **Who has VPN access → search → Give VPN access.**

## 4. Firewall API permissions

* **pfSense:** the API user AdmixCentral uses needs these privileges:
  - `api-v2-vpn-wireguard-settings-patch`, `-tunnels-get`, `-tunnel-post`, `-peers-get`, `-peer-post`, `-peer-delete`,
    `-apply-post`
  - `api-v2-interfaces-get`, `api-v2-interface-post`, `api-v2-interface-apply-post`
  - `api-v2-firewall-aliases-get`, `-alias-post`, `-rule-post`, `-apply-post`
* **OPNsense:** the API key's user needs these pages:
  - WireGuard
  - Firewall: Automation (filter and source NAT)
  - Firewall: Alias
  - Interfaces: Overview

## How it's built

| Part | Where |
|---|---|
| Tables `vpn_companies`, `vpn_sites`, `vpn_users`, `vpn_devices`, `vpn_audit_logs` | `database/migrations/2026_11_19_000001_create_vpn_tables.php` |
| pfSense / OPNsense drivers | `app/Services/Vpn/PfSenseWireGuardDriver.php`, `OpnSenseWireGuardDriver.php` |
| Devices, removals, sync | `app/Services/Vpn/VpnManager.php`, `php artisan vpn:sync` (scheduled every 15 minutes) |
| Microsoft sign-in, consent, Graph | `app/Services/Vpn/Microsoft.php` |
| Staff page / console pages | `app/Http/Controllers/Vpn/*`, `resources/views/vpn/*` |
| Portal host restriction | `app/Http/Middleware/VpnPortalHost.php` |
| Tests | `tests/Feature/VpnModuleTest.php` |

**Security notes:**
* **Keys:**
  - Client keys are generated in AdmixCentral (libsodium).
  - The private key and preshared key go to the person's browser once, as a QR code and a `data:` download. They are
    never stored or logged.
* **Sign-in tokens:**
  - The Microsoft ID token is verified: RS256 signature against Microsoft's keys, audience, lifetime and nonce.
  - The issuer must equal the token's own tenant.
  - The tenant must be linked to a company, and the person must be on that company's list.
* **What the portal touches:**
  - Firewall peers created here are named `cfbvpn-<device id>`.
  - Only such peers are ever removed. The sync also removes `cfbvpn-` peers AdmixCentral no longer knows about.

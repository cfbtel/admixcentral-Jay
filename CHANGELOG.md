# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — v0.8.6
- Updating to v0.8.5 failed on MySQL ("Identifier name … is too long"): the access group tables now use short index
  names. The migration removes the empty tables the failed update left behind and runs again; nothing else changed.
- The release tests now run on MySQL instead of SQLite.

### Added — v0.8.5
- **VPN access groups.** A company with 2 or more VPN firewalls can make groups: a name, one or more firewalls, and
  members (everyone with VPN access, people picked by hand, and/or linked Microsoft 365 groups). People use the
  firewalls of all their groups. Once a company has a group, firewalls in no group are blocked; with no groups
  everything stays open as before. Linked groups are stored per sign-in provider so other SSO can be added later.
  The sync removes devices on firewalls a person's groups no longer allow. The old "Microsoft 365 group for one
  firewall" setting is replaced: existing ones become access groups (other firewalls go into an "Everyone" group).
- Staff page: people with VPN access but no firewall get a clear message; with one location its name is shown.

### Changed — v0.8.5
- Staff page support address is help@cfbtel.com.

### Changed — v0.8.4
- The staff page's Windows steps now install **CFBTEL VPN for Windows** instead of WireGuard. The link
  (`/vpn/download/windows`, `?arch=arm64` for ARM PCs) goes straight to the newest installer on the
  cfbtel/cfbtel-vpn-windows GitHub releases (checked hourly; falls back to the releases page). Set
  `VPN_WINDOWS_REPO` in `.env` to use another repository. The AmneziaVPN tip is no longer shown for Windows.

### Fixed — v0.8.4
- Create WireGuard on pfSense: the WireGuard package check now reads the firewall's installed-package list
  (a WireGuard endpoint could answer before the package was really there, so the install was skipped and setup
  stopped with "requires the pfSense-pkg-WireGuard package"). If pfSense still reports the package missing, it is
  installed and the step is retried once; after installing, AdmixCentral waits up to a minute for it to start.
- Create WireGuard on pfSense stopped with "Field `if` must be one of [...]": pfSense's REST API can't assign a
  WireGuard tunnel as an interface. Setup no longer assigns it: the tunnel gets its address itself, the VPN rules go
  on pfSense's **WireGuard** interface group (Firewall → Rules → WireGuard), outbound NAT gets a rule for the VPN
  network (Automatic mode is switched to Hybrid, which keeps every automatic rule), and the DNS Resolver gets an
  access list entry for the VPN network. A tunnel assigned by hand keeps its interface. Clicking Create again after
  a stop finishes the "CFBTEL VPN" tunnel the earlier attempt left (same port, no devices) and skips what's there.

### Added — v0.8.3
- Sign-in for the CFBTEL VPN Windows app: the app opens the staff page (`/vpn/app`), the person signs in and picks
  the office, the device is created from the app's own public key (the private key never leaves the computer), and
  the app redeems a one-time code (`POST /vpn/app/token`, 5 minutes, once) for its tunnel settings.
- Microsoft 365 groups for VPN access: a company group (e.g. "VPN") gives its members access without adding them
  one by one, and a group per firewall limits that firewall to its members. Leaving a group removes the access at
  the next sync (15 minutes). Needs GroupMember.Read.All, which the one-click setup now grants (run it again for
  companies already set up).
- pfSense: "Create WireGuard" installs the WireGuard package (pfSense-pkg-WireGuard) first when it's missing.

### Fixed — v0.8.3
- VPN "Create WireGuard" checks the firewall's existing tunnels first: a UDP port already in use now stops with a
  clear message (adopt that tunnel or pick another port) before anything on the firewall is changed.
- System Performance tuning finds the PHP-FPM pool of the PHP version actually installed (e.g. PHP 8.4 / 8.5 at
  `/etc/php/8.5/fpm/pool.d/www.conf`) and restarts that version's PHP-FPM service; it only knew PHP 8.1–8.3.

### Fixed — v0.8.2
- Saving System Settings no longer rewrites APP_URL without its port (e.g. `https://host:26039`), which sent the
  browser to the wrong port after saving and broke the page styles until `.env` was fixed. When the host name and
  scheme are unchanged, `.env` and Nginx are left alone; SSL changes on the same host keep the custom port.

### Added — v0.8.1
- Mandrill (Mailchimp Transactional, mandrillapp.com) as a mail driver in System Settings → Email Configuration,
  sent through Mandrill's HTTPS API (messages/send-raw). The API key is stored encrypted and never shown again.
  VPN invitations use it too when the VPN's own SMTP server is left empty.

### Changed — v0.8.1
- The Mailgun API key is no longer written back into the settings page; a blank field keeps the saved key.
- A failed test email now shows the reason.

### Added — v0.8.0
- One-click Microsoft 365 setup: **Connect Microsoft 365 automatically** on a company's VPN page (or a 7-day,
  single-use link for its IT admin). A Global Administrator signs in once; AdmixCentral creates the company's own
  "CFBTEL VPN" app in its tenant with admin consent (User.Read.All; openid profile email User.Read), a 2-year
  secret, its tenant name and email domains, then removes CFBTEL's setup access. Running it again renews the secret.
  Needs a "CFBTEL VPN Setup" app (delegated permissions only) in VPN settings. The secret's expiry shows on the page.
- Email-and-password VPN accounts for companies without Microsoft Entra: email invitations with a set-password link,
  forgot-password links, lockout after 5 wrong passwords, edit / resend / remove by company admins.
- Email settings for the VPN (SMTP, sender, invitation template, test email).

### Added — v0.7.0
- Per-company Microsoft apps: a company can use its own Entra app registration (tenant ID, app ID, encrypted
  secret) instead of approving CFBTEL's shared app; its sign-in, people search and access checks use that app only.
- Work email first on the staff VPN page: the email domain picks the company and its Microsoft app (login hint).
  Email domains are set per company and must be unique.

### Fixed — v0.6.1
- Staff VPN page behind a reverse proxy (e.g. Coolify): sign-in limits use the visitor's address forwarded by the
  configured proxy IPs (VPN settings), only for that proxy on the portal host name.
- After an in-app update the first web request clears PHP-FPM's opcode cache once, so workers can't keep running
  the previous release (stale routes caused "Route not defined" errors until PHP-FPM was restarted).

### Added — VPN Access (WireGuard + Microsoft 365)
- Per-company self-service WireGuard remote access for pfSense and OPNsense: CFBTEL admins connect a company's
  Microsoft 365 (admin consent) and build WireGuard on its firewall (tunnel, rules, WAN rule, OPNsense outbound NAT)
  or adopt an existing tunnel.
- Company admins give and remove VPN access by picking people from their own Microsoft 365.
- Staff VPN page on its own host name (e.g. wguard.cfbtel.com) with Microsoft 365 sign-in, QR code / `.conf`
  setup for WireGuard or AmneziaVPN, and device removal; the console isn't served on that host.
- `vpn:sync` every 15 minutes removes devices of people who lost access or whose account was disabled or deleted.
- See docs/VPN-MODULE.md.

### Added — J Behi's external API contribution
- Company-scoped and explicitly authorized all-company MSP inventory REST API
  with Sanctum authentication, HTTPS enforcement, rate limits and safe field lists.
- Private CLI token issuance/revocation, including explicitly authorized
  non-expiring global-administrator tokens.
- Per-firewall and bulk cached telemetry endpoints with isolated background
  collection, freshness metadata, interface rates and supported VPN status.
- OpenAPI 1.2 contract, installation/operations documentation, Postman/Python
  examples and API authentication/isolation/collector regression tests.

### Security
- Pin patched league/commonmark 2.10.4 and symfony/http-foundation 7.4.21.

## [0.4.4] - 2026-02-13

### Changed
- **Release Pipeline**: Temporarily disabled Minisign verification in release workflow to restore automated release publishing.

## [0.4.3] - 2026-02-13

### Added
- **System Update Manager**: Migrated system update functionality to the System Settings card with "Check" and "Install" capabilities.
- **Update Checks**: Integrated GitHub Releases API for version checking.

## [0.4.2] - 2026-02-13

### Changed
- Internal release for testing deployment pipelines.

## [0.4.1] - 2026-02-04

### Fixed
- **Apply Changes Persistence**: Fixed issue where the "Apply Changes" banner would persist after application by standardizing dirty state detection in `/var/run`.
- **Apply Logic Refactor**: Refactored `PfSenseApiService` to handle dirty states generically for Tunables, Rules, NAT, Aliases, and Interfaces.

## [0.4.0] - 2026-01-22

### Added
- **Flicker-Free Dashboard**: Implemented global `x-cloak` support and optimistic initialization logic to ensure a smooth, stable page load experience.

### Fixed
- **Overlay Flashing**: Resolved a race condition where offline overlays would briefly appear during Alpine.js initialization.
- **Connection State Logic**: Refined the initial `online` state evaluation within the `firewallCard` component to prevent false-offline indicators during background data syncing.

## [0.3.1] - 2026-01-22

### Fixed
- **Swap Usage Detection**: Enhanced `PfSenseApiService` to support deep-nested metrics and multiple naming variations for Swap, Memory, and CPU.
- **Metric Formatting**: Added automatic parsing for percentage strings (e.g., "5.2%") into numeric values for UI bars.
- **Uptime/System Fallbacks**: Added multiple fallback keys for Uptime and Temperature to support different pfSense API implementations.

## [0.3.0] - 2026-01-22

### Added
- **Centralized Dashboard Coordinator**: Implemented `dashboardCoordinator` to manage simultaneous firewall updates, eliminating the "waterfall" effect.
- **Failover Batch Sync**: Added automatic single-request batch fetching for when WebSockets are disconnected.
- **Data Resilience**: Cached metrics are now preserved for offline devices, ensuring dashboard cards stay populated with last-known data behind the blur overlay.

### Changed
- **Performance Optimization**: Removed per-card `fetchStatus()` on initialization, reducing page load overhead significantly.
- **API Schema Flattening**: Flattened the `PfSenseApiService` response structure to simplify metric binding on the frontend.
- **Unified Update Pipeline**: Standardized the data format shared between WebSockets, Ajax, and background jobs.

### Fixed
- **Metric Mapping Issues**: Fixed "Unknown" values for CPU, Memory, and Version by unifying nested and flat data paths in Alpine components.
- **Dashboard Data Freezing**: Resolved issues where real-time updates were ignored due to property structure mismatches.
- **Offline UI Breakage**: Fixed cards disappearing or being cleared when a firewall becomes unreachable.

## [0.2.0] - 2026-01-22

### Added
- **Firewall Counter Display**: Added "Showing X of Y firewalls" counter with real-time filtering support on dashboard and firewalls index pages
- **Shared Filterable Mixin**: Created reusable `window.filterableMixin()` component for consistent filtering across pages
- **URL-Persisted Filters**: Search, status, and customer filters now persist in URL query parameters and survive page refreshes
- **Settings Page Restore**: Added "Restore to Default" buttons for logo and favicon in system settings
- **Gateway Display Fallback**: Offline firewalls now show WAN gateway with "Unknown" status instead of empty section
- **Documentation**: Added usage guide for filterable mixin at `.agent/filterable-mixin-usage.md`

### Changed
- **Gateway UI Redesign**: Updated gateway display with neutral backgrounds and color-coded left borders
- **Table Spacing**: Increased vertical padding in System Information tables for better readability
- **Gateway Labels**: Standardized gateway labels to use `text-sm` font size across all pages
- **Project Organization**: Moved deployment scripts (`install.sh`, `setup_reverb.sh`) to `/scripts` directory
- **Route Names**: Updated system settings routes from `system.customization.*` to `system.settings.*`

### Fixed
- **Settings Page Error**: Fixed "Route [system.customization.index] not defined" error when saving settings
- **Layout Stability**: Resolved issue where gateway section disappeared entirely for offline firewalls
- **Code Duplication**: Reduced ~100+ lines of duplicate filtering logic by using shared mixin

### Technical
- Refactored dashboard and firewalls index pages to use shared `filterableMixin`
- Added `device-updated` event with detailed payload (id, online status)
- Implemented reactive filtering with Alpine.js computed properties
- Enhanced event-driven architecture for real-time status updates

## [0.1.0] - Initial Release

### Added
- Initial AdmixCentral application for pfSense firewall management
- Dashboard with firewall status monitoring
- Real-time status updates via WebSocket (Reverb)
- Queue-based background job processing
- Multi-tenant architecture with company isolation
- System settings management
- Custom logo and favicon support
- Dark/light theme support

[Unreleased]: https://github.com/geekasso/admixcentral/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/geekasso/admixcentral/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/geekasso/admixcentral/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/geekasso/admixcentral/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/geekasso/admixcentral/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/geekasso/admixcentral/releases/tag/v0.1.0

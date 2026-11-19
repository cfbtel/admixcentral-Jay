@php
    $btn = 'inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-700';
    $card = 'bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 text-gray-900 dark:text-gray-100';
    $input = 'mt-1 block w-full border-gray-300 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 focus:border-indigo-500 focus:ring-indigo-500 rounded-md shadow-sm text-sm';
    $label = 'block text-sm font-medium text-gray-700 dark:text-gray-300';
    $th = 'px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider';
    $td = 'px-3 py-2 text-sm';
@endphp
<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">VPN (WireGuard + Microsoft 365)</h2>
    </x-slot>

    <div class="py-8">
        <div class="max-w-5xl mx-auto sm:px-6 lg:px-8 space-y-6">
            @include('vpn.admin._notices')

            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-3">Companies</h3>
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead><tr><th class="{{ $th }}">Company</th><th class="{{ $th }}">Microsoft 365</th><th class="{{ $th }}">VPN firewalls</th><th class="{{ $th }}">People</th></tr></thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                    @foreach($companies as $row)
                        <tr>
                            <td class="{{ $td }}"><a class="text-indigo-600 dark:text-indigo-400 font-medium" href="{{ route('vpn.company', $row['company']) }}">{{ $row['company']->name }}</a></td>
                            <td class="{{ $td }}">{{ $row['tenant'] ?? '—' }}</td>
                            <td class="{{ $td }}">{{ $row['sites'] }}</td>
                            <td class="{{ $td }}">{{ $row['people'] }}</td>
                        </tr>
                    @endforeach
                    </tbody>
                </table>
            </div>

            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-1">Settings</h3>
                <p class="text-sm text-gray-500 mb-4">
                    One multi-tenant app registration in CFBTEL's Microsoft Entra ("Accounts in any organizational directory").
                    Redirect URIs (Web): <code>{{ $redirects[0] }}</code> and <code>{{ $redirects[1] }}</code>.
                    API permissions (Microsoft Graph): delegated <code>openid</code>, <code>profile</code>, <code>email</code>, <code>User.Read</code>; application <code>User.Read.All</code>, then grant admin consent.
                </p>
                <form method="POST" action="{{ route('vpn.settings.update') }}" class="space-y-4 max-w-xl">@csrf
                    <label class="{{ $label }}">Application (client) ID<input name="ms_client_id" value="{{ old('ms_client_id', $clientId) }}" placeholder="00000000-0000-0000-0000-000000000000" class="{{ $input }}" autocomplete="off"></label>
                    <label class="{{ $label }}">Client secret {{ $hasSecret ? '(saved — leave blank to keep it)' : '' }}<input name="ms_client_secret" type="password" class="{{ $input }}" autocomplete="new-password"></label>
                    <label class="{{ $label }}">Staff VPN page host name<input name="portal_host" value="{{ old('portal_host', $portalHost) }}" placeholder="wguard.cfbtel.com" class="{{ $input }}"></label>
                    <p class="text-xs text-gray-500">Only the VPN pages are served on this name; the AdmixCentral console isn't. Point its DNS and reverse proxy at this server.</p>
                    <label class="{{ $label }}">Reverse proxy IPs in front of the staff page (optional)<input name="proxy_ips" value="{{ old('proxy_ips', $proxyIps) }}" placeholder="66.70.138.81" class="{{ $input }}"></label>
                    <p class="text-xs text-gray-500">Only needed when the staff page is reached through a proxy (e.g. Coolify): its forwarded visitor address is then used for sign-in limits.</p>
                    <label class="{{ $label }}">Devices per person<input name="max_devices" value="{{ old('max_devices', $maxDevices) }}" inputmode="numeric" class="{{ $input }}"></label>
                    <button class="{{ $btn }}">Save</button>
                </form>
            </div>
        </div>
    </div>
</x-app-layout>

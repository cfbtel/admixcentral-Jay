@php
    $btn = 'inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-700';
    $btn2 = 'inline-flex items-center px-3 py-1.5 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-500 rounded-md font-semibold text-xs text-gray-700 dark:text-gray-200 uppercase tracking-widest hover:bg-gray-50 dark:hover:bg-gray-600';
    $btnRed = 'inline-flex items-center px-3 py-1.5 bg-red-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-red-500';
    $card = 'bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 text-gray-900 dark:text-gray-100';
    $input = 'border-gray-300 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 focus:border-indigo-500 focus:ring-indigo-500 rounded-md shadow-sm text-sm';
    $th = 'px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider';
    $td = 'px-3 py-2 text-sm';
@endphp
<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">{{ $company->name }} – VPN (WireGuard)</h2>
        <div class="mt-1 text-sm text-gray-500 dark:text-gray-400">
            <a href="{{ route('companies.show', $company) }}" class="font-medium text-indigo-600 hover:text-indigo-800 dark:text-indigo-400">{{ $company->name }}</a>
            <span class="mx-2 text-gray-300 dark:text-gray-600">/</span> VPN
        </div>
    </x-slot>

    <div class="py-8">
        <div class="max-w-full mx-auto sm:px-6 lg:px-8 space-y-6">
            @include('vpn.admin._notices')

            <div class="{{ $card }}">
                <p class="text-sm text-gray-600 dark:text-gray-300">
                    People this company gives VPN access sign in at <a class="text-indigo-600 dark:text-indigo-400 underline" href="{{ $portalUrl }}" target="_blank" rel="noopener">{{ $portalUrl }}</a>
                    with their own Microsoft 365 account and add up to {{ \App\Services\Vpn\VpnSettings::maxDevices() }} devices (WireGuard or AmneziaVPN app).
                </p>
            </div>

            {{-- 1. Microsoft 365 --}}
            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-3">1. Microsoft 365</h3>
                @if($vc->ms_tenant_id)
                    <p class="text-sm">✓ Connected to <strong>{{ $vc->ms_tenant_name ?? $vc->ms_tenant_id }}</strong> <span class="text-gray-500">({{ $vc->ms_tenant_id }})</span></p>
                @elseif($consentError)
                    <p class="text-sm text-red-600 dark:text-red-400">{{ $consentError }} @if(auth()->user()->isGlobalAdmin())<a class="underline" href="{{ route('vpn.settings') }}">VPN settings</a>@endif</p>
                @else
                    <p class="text-sm mb-3">Not connected. A Global Administrator of this company's Microsoft 365 approves the CFBTEL VPN app once (sign-in, and reading users so you can pick people).</p>
                    @if($canManage)
                        <a href="{{ $consentUrl }}" class="{{ $btn }}">Connect Microsoft 365</a>
                        <label class="block mt-3 text-xs text-gray-500">Or send this link to the company's Microsoft 365 admin (valid 7 days)
                            <input readonly value="{{ $consentUrl }}" class="mt-1 w-full {{ $input }}" onclick="this.select()">
                        </label>
                    @endif
                @endif
            </div>

            {{-- 2. Firewalls --}}
            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-3">2. Firewalls</h3>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead><tr><th class="{{ $th }}">Firewall</th><th class="{{ $th }}">Type</th><th class="{{ $th }}">VPN</th><th class="{{ $th }}">Endpoint</th><th class="{{ $th }}">VPN network</th><th class="{{ $th }}"></th></tr></thead>
                        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        @forelse($firewalls as $fw)
                            @php $s = $sites[$fw->id] ?? null; @endphp
                            <tr>
                                <td class="{{ $td }} font-medium">{{ $fw->name }}</td>
                                <td class="{{ $td }}">{{ $fw->os_display_name }}</td>
                                <td class="{{ $td }}">
                                    @if(!$s) <span class="text-gray-400">off</span>
                                    @elseif($s->isReady()) <span class="text-green-600 dark:text-green-400 font-semibold">ready</span>
                                    @else <span class="text-yellow-600 dark:text-yellow-400">{{ $s->status }}</span> @endif
                                </td>
                                <td class="{{ $td }}">{{ $s?->endpoint ?? '—' }}</td>
                                <td class="{{ $td }}">{{ $s?->subnet ?? '—' }}</td>
                                <td class="{{ $td }} text-right">
                                    @if($s)
                                        <a href="{{ route('vpn.site', [$company, $s]) }}" class="{{ $btn2 }}">{{ $s->isReady() ? 'Settings' : 'Set up' }}</a>
                                    @elseif($canManage)
                                        <form method="POST" action="{{ route('vpn.firewall.enable', [$company, $fw]) }}" class="inline">@csrf<button class="{{ $btn2 }}">Enable VPN</button></form>
                                    @endif
                                </td>
                            </tr>
                        @empty
                            <tr><td colspan="6" class="{{ $td }} text-gray-500">This company has no firewalls in AdmixCentral yet.</td></tr>
                        @endforelse
                        </tbody>
                    </table>
                </div>
            </div>

            {{-- 3. People --}}
            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-3">3. Who has VPN access</h3>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead><tr><th class="{{ $th }}">Person</th><th class="{{ $th }}">Devices</th><th class="{{ $th }}">Last sign-in</th><th class="{{ $th }}">Added by</th><th class="{{ $th }}"></th></tr></thead>
                        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        @forelse($users as $u)
                            <tr>
                                <td class="{{ $td }}"><div class="font-medium">{{ $u->name }}</div><div class="text-xs text-gray-500">{{ $u->upn }}</div></td>
                                <td class="{{ $td }}">{{ $u->active_devices_count }}</td>
                                <td class="{{ $td }}">{{ $u->last_login_at?->diffForHumans() ?? 'never' }}</td>
                                <td class="{{ $td }} text-xs text-gray-500">{{ $u->added_by }}</td>
                                <td class="{{ $td }} text-right">
                                    @if($canManage)
                                        <form method="POST" action="{{ route('vpn.users.remove', [$company, $u]) }}" class="inline" onsubmit="return confirm('Remove this person\'s VPN access? Their devices stop working right away.')">@csrf<button class="{{ $btnRed }}">Remove access</button></form>
                                    @endif
                                </td>
                            </tr>
                        @empty
                            <tr><td colspan="5" class="{{ $td }} text-gray-500">Nobody has VPN access yet.</td></tr>
                        @endforelse
                        </tbody>
                    </table>
                </div>

                @if($canManage)
                    <h4 class="font-semibold mt-6 mb-2">Give someone VPN access</h4>
                    @if($vc->ms_tenant_id)
                        <form method="GET" action="{{ route('vpn.company', $company) }}" class="flex gap-2 max-w-xl">
                            <input name="q" value="{{ $q }}" placeholder="Search this company's Microsoft 365 by name or email" class="flex-1 {{ $input }}">
                            <button class="{{ $btn2 }}" name="search" value="1">Search</button>
                        </form>
                        @if($searchError)<p class="mt-2 text-sm text-red-600 dark:text-red-400">{{ $searchError }}</p>@endif
                        @if($results !== null)
                            <ul class="mt-3 divide-y divide-gray-200 dark:divide-gray-700 max-w-xl">
                                @forelse($results as $r)
                                    <li class="py-2 flex items-center justify-between gap-3">
                                        <div><div class="text-sm font-medium">{{ $r['name'] }}</div><div class="text-xs text-gray-500">{{ $r['mail'] ?? $r['upn'] }}@if($r['guest']) · guest @endif</div></div>
                                        <form method="POST" action="{{ route('vpn.users.store', $company) }}">@csrf<input type="hidden" name="oid" value="{{ $r['oid'] }}"><button class="{{ $btn2 }}">Give VPN access</button></form>
                                    </li>
                                @empty
                                    <li class="py-2 text-sm text-gray-500">No matching people{{ $q !== '' ? " for “{$q}”" : '' }}.</li>
                                @endforelse
                            </ul>
                        @endif
                    @else
                        <p class="text-sm text-gray-500">Connect Microsoft 365 first.</p>
                    @endif
                @endif
            </div>

            {{-- 4. Devices --}}
            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-3">4. Devices</h3>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead><tr><th class="{{ $th }}">Person</th><th class="{{ $th }}">Device</th><th class="{{ $th }}">Firewall</th><th class="{{ $th }}">Address</th><th class="{{ $th }}">Added</th><th class="{{ $th }}"></th></tr></thead>
                        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        @forelse($devices as $d)
                            <tr>
                                <td class="{{ $td }}">{{ $d->user?->upn ?? '(access removed)' }}</td>
                                <td class="{{ $td }}">{{ $d->name }}</td>
                                <td class="{{ $td }}">{{ $d->site?->firewall?->name }}</td>
                                <td class="{{ $td }}">{{ $d->address }}</td>
                                <td class="{{ $td }}">{{ $d->created_at?->diffForHumans() }}</td>
                                <td class="{{ $td }} text-right">
                                    @if($d->revoked_at)
                                        <span class="text-xs text-yellow-600 dark:text-yellow-400">being removed</span>
                                    @elseif($canManage)
                                        <form method="POST" action="{{ route('vpn.devices.remove', [$company, $d]) }}" class="inline">@csrf<button class="{{ $btnRed }}">Remove</button></form>
                                    @endif
                                </td>
                            </tr>
                        @empty
                            <tr><td colspan="6" class="{{ $td }} text-gray-500">No devices yet.</td></tr>
                        @endforelse
                        </tbody>
                    </table>
                </div>
            </div>

            {{-- Activity --}}
            <div class="{{ $card }}">
                <h3 class="text-lg font-bold mb-3">Activity</h3>
                <ul class="text-sm space-y-1">
                    @forelse($audit as $a)
                        <li><span class="text-xs text-gray-500">{{ $a->created_at }} · {{ $a->actor }}</span> {{ $a->action }}</li>
                    @empty
                        <li class="text-gray-500">Nothing yet.</li>
                    @endforelse
                </ul>
            </div>
        </div>
    </div>
</x-app-layout>

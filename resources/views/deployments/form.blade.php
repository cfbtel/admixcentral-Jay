@php
    $card = 'bg-white dark:bg-gray-800 shadow-sm sm:rounded-lg';
    $label = 'block text-sm font-medium text-gray-700 dark:text-gray-200';
    $input = 'mt-1 block w-full rounded-md border-gray-300 text-sm shadow-sm focus:border-brand-500 focus:ring-brand-500 dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100';
    $help = 'mt-1 text-xs text-gray-500 dark:text-gray-400';
    $kinds = \App\Services\Deploy\DeployItems::KINDS;
@endphp
<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">{{ $deployment ? 'Edit deployment' : 'New deployment' }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">The same changes on many firewalls. Each firewall is checked first; nothing changes until you start a wave.</p>
    </x-slot>

<script>
window.deployForm = function (cfg) {
    const blank = {
        rule: () => ({ kind: 'rule', action: 'pass', interface: 'WAN', ipprotocol: 'inet', protocol: 'tcp', source: 'any', source_port: '', destination: 'any', destination_port: '', descr: '', placement: 'top', log: false }),
        alias: () => ({ kind: 'alias', name: '', type: 'host', entries: '', descr: '', updatefreq: 1 }),
        nat: () => ({ kind: 'nat', interface: 'WAN', protocol: 'tcp', source: 'any', destination: '', destination_port: '', target: '', local_port: '', descr: '' }),
        pfb_ipv4: () => ({ kind: 'pfb_ipv4', name: '', descr: '', rows: [{ format: 'auto', state: 'Enabled', url: '', header: '' }], action: 'Deny_Inbound', cron: '01hour', dow: '1', aliaslog: 'enabled', custom: '' }),
    };
    return {
        name: cfg.name,
        items: (cfg.items || []).map(i => Object.assign(blank[i.kind] ? blank[i.kind]() : {}, i, i.kind === 'alias' && Array.isArray(i.entries) ? { entries: i.entries.join('\n') } : {})),
        firewalls: cfg.firewalls,
        selected: cfg.selected.map(Number),
        q: '',
        open: 0,
        init() {
            if (!this.items.length && cfg.startKind) { this.add(cfg.startKind); }
            this.$watch('items', () => {}, { deep: true });
        },
        add(kind) { this.items.push(blank[kind]()); this.open = this.items.length - 1; this.$nextTick(() => document.getElementById('item-' + this.open)?.scrollIntoView({ behavior: 'smooth', block: 'center' })); },
        remove(i) { this.items.splice(i, 1); this.open = Math.max(0, Math.min(this.open, this.items.length - 1)); },
        move(i, d) { const j = i + d; if (j < 0 || j >= this.items.length) return; const x = this.items.splice(i, 1)[0]; this.items.splice(j, 0, x); this.open = j; },
        get shown() { const q = this.q.trim().toLowerCase(); return this.firewalls.filter(f => !q || (f.name + ' ' + f.company).toLowerCase().includes(q)); },
        toggle(id) { const i = this.selected.indexOf(id); i === -1 ? this.selected.push(id) : this.selected.splice(i, 1); },
        allShown() { const ids = this.shown.filter(f => !f.opn).map(f => f.id); const all = ids.every(id => this.selected.includes(id)); this.selected = all ? this.selected.filter(id => !ids.includes(id)) : [...new Set([...this.selected, ...ids])]; },
        title(it) {
            const k = cfg.kinds[it.kind];
            if (it.kind === 'rule') return (it.descr || 'New rule') + ' · ' + ({ pass: 'Pass', block: 'Block', reject: 'Reject' })[it.action] + ' on ' + (it.interface || '?');
            if (it.kind === 'alias') return (it.name || 'New alias') + ' · ' + it.type;
            if (it.kind === 'nat') return (it.descr || 'New port forward') + ' · ' + (it.interface || '?') + ' ' + (it.destination_port || '?') + ' → ' + (it.target || '?');
            if (it.kind === 'pfb_ipv4') return (it.name || 'New pfBlockerNG list') + ' · ' + it.action.replace('_', ' ');
            return k;
        },
        ports(it) { return ['tcp', 'udp', 'tcp/udp'].includes(it.protocol); },
        payload() {
            return JSON.stringify(this.items.map(i => i.kind === 'alias' ? Object.assign({}, i, { entries: String(i.entries || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean) }) : i));
        },
    };
};
</script>

<div class="py-6" x-data="deployForm(@js([
        'name' => old('name', $name),
        'items' => old('items') ? json_decode(old('items'), true) : $items,
        'firewalls' => $firewalls,
        'selected' => old('firewall_ids', $selected),
        'startKind' => $startKind,
        'kinds' => $kinds,
    ]))" x-cloak>
    <form method="POST" action="{{ $deployment ? route('deployments.update', $deployment) : route('deployments.store') }}" class="max-w-5xl mx-auto sm:px-6 lg:px-8 space-y-5" @submit="$refs.items.value = payload()">
        @csrf
        @if($deployment) @method('PUT') @endif
        <input type="hidden" name="items" x-ref="items">
        <template x-for="id in selected" :key="id"><input type="hidden" name="firewall_ids[]" :value="id"></template>

        <a href="{{ $deployment ? route('deployments.show', $deployment) : route('deployments.index') }}" class="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m12 5-5 5 5 5" stroke-linecap="round" stroke-linejoin="round"/></svg>{{ $deployment ? 'Back to the deployment' : 'All deployments' }}
        </a>

        @if($errors->any())
            <div class="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-200" role="alert">
                <p class="font-medium">Please fix:</p>
                <ul class="mt-1 list-disc pl-5">@foreach($errors->all() as $e)<li>{{ $e }}</li>@endforeach</ul>
            </div>
        @endif

        <section class="{{ $card }} p-6">
            <label class="{{ $label }}">Name
                <input name="name" x-model="name" maxlength="120" placeholder="For example: RDP allow list on all DCs" class="{{ $input }}">
            </label>
            <p class="{{ $help }}">Shown in the list of deployments and in each firewall's configuration history.</p>
        </section>

        {{-- Changes --}}
        <section class="{{ $card }}">
            <header class="flex flex-wrap items-center gap-3 border-b border-gray-100 px-6 py-4 dark:border-gray-700">
                <div class="min-w-0 flex-1">
                    <h3 class="text-base font-semibold text-gray-900 dark:text-white">Changes</h3>
                    <p class="text-sm text-gray-500 dark:text-gray-400">Applied in this order, all in one save on each firewall. Something with the same name (or, for rules and port forwards, the same description on the same interface) is updated to match.</p>
                </div>
            </header>

            <ol class="divide-y divide-gray-100 dark:divide-gray-700/70">
                <template x-for="(it, i) in items" :key="i">
                    <li :id="'item-' + i" class="px-6 py-4">
                        <div class="flex items-center gap-3">
                            <button type="button" @click="open = open === i ? -1 : i" class="flex min-w-0 flex-1 items-center gap-3 text-left">
                                <span class="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-gray-100 text-xs font-semibold tabular-nums text-gray-600 dark:bg-gray-700 dark:text-gray-300" x-text="i + 1"></span>
                                <span class="shrink-0 rounded bg-brand-50 px-1.5 py-0.5 text-xs font-medium text-brand-800 dark:bg-brand-950 dark:text-brand-200" x-text="@js($kinds)[it.kind]"></span>
                                <span class="truncate text-sm font-medium text-gray-900 dark:text-gray-100" x-text="title(it)"></span>
                            </button>
                            <button type="button" @click="move(i, -1)" :disabled="i === 0" class="rounded p-1 text-gray-500 hover:bg-gray-100 disabled:opacity-30 dark:hover:bg-gray-700" aria-label="Move up"><svg class="h-4 w-4" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="m5 12 5-5 5 5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
                            <button type="button" @click="move(i, 1)" :disabled="i === items.length - 1" class="rounded p-1 text-gray-500 hover:bg-gray-100 disabled:opacity-30 dark:hover:bg-gray-700" aria-label="Move down"><svg class="h-4 w-4" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="m5 8 5 5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
                            <button type="button" @click="remove(i)" class="rounded px-2 py-1 text-sm font-medium text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-950">Remove</button>
                        </div>

                        <div x-show="open === i" class="mt-4 grid gap-4 sm:grid-cols-2">
                            {{-- Firewall rule --}}
                            <template x-if="it.kind === 'rule'">
                                <div class="contents">
                                    <label class="{{ $label }}">Action
                                        <select x-model="it.action" class="{{ $input }}"><option value="pass">Pass (allow)</option><option value="block">Block (drop silently)</option><option value="reject">Reject</option></select>
                                    </label>
                                    <label class="{{ $label }}">Interface
                                        <input x-model="it.interface" list="pfc-ifaces" class="{{ $input }}" placeholder="WAN">
                                        <span class="{{ $help }} block">Name (WAN, LAN, OPT1) or the description it has on the firewall.</span>
                                    </label>
                                    <label class="{{ $label }}">Protocol
                                        <select x-model="it.protocol" class="{{ $input }}"><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp/udp">TCP and UDP</option><option value="icmp">ICMP</option></select>
                                    </label>
                                    <label class="{{ $label }}">IP version
                                        <select x-model="it.ipprotocol" class="{{ $input }}"><option value="inet">IPv4</option><option value="inet6">IPv6</option><option value="inet46">IPv4 and IPv6</option></select>
                                    </label>
                                    <label class="{{ $label }}">Source
                                        <input x-model="it.source" class="{{ $input }}" placeholder="any">
                                        <span class="{{ $help }} block">any, an IP or network (10.0.0.0/24), an alias (pfB_RDPDC0pfblocker), or lannet / wanip. Start with ! to mean "not".</span>
                                    </label>
                                    <label class="{{ $label }}" x-show="ports(it)">Source port
                                        <input x-model="it.source_port" class="{{ $input }}" placeholder="Usually empty">
                                    </label>
                                    <label class="{{ $label }}">Destination
                                        <input x-model="it.destination" class="{{ $input }}" placeholder="any">
                                        <span class="{{ $help }} block">Same as source, plus "self" for the firewall itself, or wanip / lanip.</span>
                                    </label>
                                    <label class="{{ $label }}" x-show="ports(it)">Destination port
                                        <input x-model="it.destination_port" class="{{ $input }}" placeholder="3389, 8000-8010 or a port alias">
                                    </label>
                                    <label class="{{ $label }} sm:col-span-2">Description
                                        <input x-model="it.descr" maxlength="200" class="{{ $input }}" placeholder="Allow RDP from the RDP allow list" required>
                                        <span class="{{ $help }} block">Required: PFCentral finds this rule again by its description on that interface, to update or undo it.</span>
                                    </label>
                                    <label class="{{ $label }}">Where in the rule list
                                        <select x-model="it.placement" class="{{ $input }}"><option value="top">At the top (checked first)</option><option value="bottom">At the bottom</option></select>
                                        <span class="{{ $help }} block">For a new rule. A rule that is updated keeps its place.</span>
                                    </label>
                                    <label class="flex items-center gap-2 self-end pb-2 text-sm text-gray-700 dark:text-gray-200"><input type="checkbox" x-model="it.log" class="rounded border-gray-300 text-brand-600 focus:ring-brand-500 dark:border-gray-600"> Log packets that match</label>
                                </div>
                            </template>

                            {{-- Alias --}}
                            <template x-if="it.kind === 'alias'">
                                <div class="contents">
                                    <label class="{{ $label }}">Name
                                        <input x-model="it.name" maxlength="31" class="{{ $input }}" placeholder="RDP_Allowed">
                                        <span class="{{ $help }} block">Letters, numbers and underscores.</span>
                                    </label>
                                    <label class="{{ $label }}">Type
                                        <select x-model="it.type" class="{{ $input }}"><option value="host">Hosts</option><option value="network">Networks</option><option value="port">Ports</option><option value="url">URL (IPs, loaded once)</option><option value="urltable">URL table (IPs, refreshed)</option></select>
                                    </label>
                                    <label class="{{ $label }} sm:col-span-2">Entries
                                        <textarea x-model="it.entries" rows="4" class="{{ $input }} font-mono" placeholder="One per line"></textarea>
                                        <span class="{{ $help }} block" x-text="it.type === 'url' || it.type === 'urltable' ? 'The URL of a text file with one IP or network per line.' : (it.type === 'port' ? 'Ports or ranges like 8000:8010.' : 'IP addresses, networks, host names or other aliases.')"></span>
                                    </label>
                                    <label class="{{ $label }}" x-show="it.type === 'urltable'">Refresh every (days)
                                        <input type="number" min="1" max="365" x-model.number="it.updatefreq" class="{{ $input }}">
                                    </label>
                                    <label class="{{ $label }}">Description
                                        <input x-model="it.descr" maxlength="250" class="{{ $input }}">
                                    </label>
                                </div>
                            </template>

                            {{-- Port forward --}}
                            <template x-if="it.kind === 'nat'">
                                <div class="contents">
                                    <label class="{{ $label }}">Interface
                                        <input x-model="it.interface" list="pfc-ifaces" class="{{ $input }}" placeholder="WAN">
                                    </label>
                                    <label class="{{ $label }}">Protocol
                                        <select x-model="it.protocol" class="{{ $input }}"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp/udp">TCP and UDP</option></select>
                                    </label>
                                    <label class="{{ $label }}">Outside port
                                        <input x-model="it.destination_port" class="{{ $input }}" placeholder="3389">
                                    </label>
                                    <label class="{{ $label }}">Outside address
                                        <input x-model="it.destination" class="{{ $input }}" placeholder="The interface's address">
                                        <span class="{{ $help }} block">Leave empty for the interface's own address, or enter a virtual IP.</span>
                                    </label>
                                    <label class="{{ $label }}">Internal address
                                        <input x-model="it.target" class="{{ $input }}" placeholder="192.168.1.10">
                                    </label>
                                    <label class="{{ $label }}">Internal port
                                        <input x-model="it.local_port" class="{{ $input }}" placeholder="Same as outside">
                                    </label>
                                    <label class="{{ $label }}">Allowed from
                                        <input x-model="it.source" class="{{ $input }}" placeholder="any">
                                        <span class="{{ $help }} block">any, an IP or network, or an alias such as a pfBlockerNG list (pfB_…).</span>
                                    </label>
                                    <label class="{{ $label }}">Description
                                        <input x-model="it.descr" maxlength="200" class="{{ $input }}" placeholder="RDP to DC01" required>
                                        <span class="{{ $help }} block">Required. A matching pass rule is added and kept with it.</span>
                                    </label>
                                </div>
                            </template>

                            {{-- pfBlockerNG IPv4 list --}}
                            <template x-if="it.kind === 'pfb_ipv4'">
                                <div class="contents">
                                    <label class="{{ $label }}">Name
                                        <input x-model="it.name" maxlength="24" class="{{ $input }}" placeholder="RDPDC0pfblocker">
                                        <span class="{{ $help }} block">Up to 24 letters, numbers and underscores. Its alias on the firewall is pfB_ plus this name.</span>
                                    </label>
                                    <label class="{{ $label }}">Description
                                        <input x-model="it.descr" maxlength="250" class="{{ $input }}" placeholder="RDP Dynamic IP Allow List">
                                    </label>
                                    <div class="sm:col-span-2">
                                        <span class="{{ $label }}">Sources</span>
                                        <template x-for="(r, ri) in it.rows" :key="ri">
                                            <div class="mt-2 flex flex-wrap items-center gap-2">
                                                <select x-model="r.format" style="width:8rem" class="rounded-md border-gray-300 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100" aria-label="Format"><option value="auto">Auto</option><option value="rsync">RSync</option><option value="geoip">GeoIP</option><option value="asn">ASN</option><option value="whois">Whois</option><option value="regex">Regex</option></select>
                                                <select x-model="r.state" style="width:6.5rem" class="rounded-md border-gray-300 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100" aria-label="State"><option value="Enabled">On</option><option value="Flex">Flex</option><option value="Hold">Hold</option><option value="Disabled">Off</option></select>
                                                <input x-model="r.url" style="flex:1 1 16rem;min-width:12rem" class="rounded-md border-gray-300 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100" placeholder="https://… /ip.txt" aria-label="Source URL">
                                                <input x-model="r.header" style="width:11rem" class="rounded-md border-gray-300 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100" placeholder="Header" aria-label="Header">
                                                <button type="button" @click="it.rows.splice(ri, 1)" class="rounded px-2 text-sm font-medium text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-950">Remove</button>
                                            </div>
                                        </template>
                                        <button type="button" @click="it.rows.push({ format: 'auto', state: 'Enabled', url: '', header: '' })" class="mt-2 text-sm font-medium text-brand-700 hover:underline dark:text-brand-300">+ Add a source</button>
                                    </div>
                                    <label class="{{ $label }}">Action
                                        <select x-model="it.action" class="{{ $input }}">
                                            @foreach(['Deny_Inbound' => 'Deny inbound', 'Deny_Outbound' => 'Deny outbound', 'Deny_Both' => 'Deny both', 'Permit_Inbound' => 'Permit inbound', 'Permit_Outbound' => 'Permit outbound', 'Permit_Both' => 'Permit both', 'Match_Inbound' => 'Match inbound', 'Match_Outbound' => 'Match outbound', 'Match_Both' => 'Match both', 'Alias_Deny' => 'Alias only: deny', 'Alias_Permit' => 'Alias only: permit', 'Alias_Match' => 'Alias only: match', 'Alias_Native' => 'Alias only: native', 'Disabled' => 'Disabled'] as $v => $t)
                                                <option value="{{ $v }}">{{ $t }}</option>
                                            @endforeach
                                        </select>
                                        <span class="{{ $help }} block">"Alias only" makes the pfB_ alias for your own rules (for example a port forward allowed only from this list).</span>
                                    </label>
                                    <label class="{{ $label }}">Update frequency
                                        <select x-model="it.cron" class="{{ $input }}">
                                            @foreach(['Never' => 'Never', '01hour' => 'Every hour', '02hours' => 'Every 2 hours', '03hours' => 'Every 3 hours', '04hours' => 'Every 4 hours', '06hours' => 'Every 6 hours', '08hours' => 'Every 8 hours', '12hours' => 'Every 12 hours', 'EveryDay' => 'Once a day', 'Weekly' => 'Weekly'] as $v => $t)
                                                <option value="{{ $v }}">{{ $t }}</option>
                                            @endforeach
                                        </select>
                                    </label>
                                    <label class="{{ $label }}" x-show="it.cron === 'Weekly'">Day of the week
                                        <select x-model="it.dow" class="{{ $input }}">
                                            @foreach(['1' => 'Monday', '2' => 'Tuesday', '3' => 'Wednesday', '4' => 'Thursday', '5' => 'Friday', '6' => 'Saturday', '7' => 'Sunday'] as $v => $t)
                                                <option value="{{ $v }}">{{ $t }}</option>
                                            @endforeach
                                        </select>
                                    </label>
                                    <label class="{{ $label }}">Logging
                                        <select x-model="it.aliaslog" class="{{ $input }}"><option value="enabled">On</option><option value="disabled">Off</option></select>
                                    </label>
                                    <label class="{{ $label }} sm:col-span-2">Custom list (optional)
                                        <textarea x-model="it.custom" rows="3" class="{{ $input }} font-mono" placeholder="Extra IPs or networks, one per line"></textarea>
                                    </label>
                                    <p class="sm:col-span-2 rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-200">Needs pfBlockerNG (version 3 or newer) on the firewall. Firewalls without it are skipped and listed so you can install it and retry. After deploying, pfBlockerNG updates its lists by itself.</p>
                                </div>
                            </template>
                        </div>
                    </li>
                </template>
            </ol>

            <div class="flex flex-wrap items-center gap-2 border-t border-gray-100 px-6 py-4 dark:border-gray-700">
                <span class="text-sm text-gray-500 dark:text-gray-400">Add:</span>
                @foreach($kinds as $k => $t)
                    <button type="button" @click="add('{{ $k }}')" class="rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-700">{{ $t }}</button>
                @endforeach
            </div>
        </section>

        {{-- Firewalls --}}
        <section class="{{ $card }}">
            <header class="flex flex-wrap items-center gap-3 border-b border-gray-100 px-6 py-4 dark:border-gray-700">
                <div class="min-w-0 flex-1">
                    <h3 class="text-base font-semibold text-gray-900 dark:text-white">Firewalls</h3>
                    <p class="text-sm text-gray-500 dark:text-gray-400"><span class="tabular-nums" x-text="selected.length"></span> selected. The first one becomes wave 1, the test; the rest are wave 2. You can change waves on the next page.</p>
                </div>
                <input x-model="q" type="search" placeholder="Search firewalls or companies" class="w-64 rounded-md border-gray-300 text-sm dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100">
                <button type="button" @click="allShown()" class="text-sm font-medium text-brand-700 hover:underline dark:text-brand-300">Select / clear shown</button>
            </header>
            <ul class="max-h-96 divide-y divide-gray-100 overflow-y-auto dark:divide-gray-700/70">
                <template x-for="f in shown" :key="f.id">
                    <li>
                        <label class="flex items-center gap-3 px-6 py-2.5" :class="f.opn ? 'opacity-60' : 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/40'">
                            <input type="checkbox" :checked="selected.includes(f.id)" @change="toggle(f.id)" :disabled="f.opn" class="rounded border-gray-300 text-brand-600 focus:ring-brand-500 dark:border-gray-600">
                            <span class="min-w-0 flex-1">
                                <span class="block text-sm font-medium text-gray-900 dark:text-gray-100" x-text="f.name"></span>
                                <span class="block text-xs text-gray-500 dark:text-gray-400" x-text="f.company + (f.opn ? ' · OPNsense, not supported yet' : '')"></span>
                            </span>
                            <span x-show="selected.indexOf(f.id) === 0" class="rounded-full bg-brand-50 px-2 py-0.5 text-xs font-medium text-brand-800 dark:bg-brand-950 dark:text-brand-200">Wave 1</span>
                        </label>
                    </li>
                </template>
                <li x-show="!shown.length" class="px-6 py-6 text-center text-sm text-gray-500">No firewalls match.</li>
            </ul>
        </section>

        <div class="flex items-center justify-end gap-3">
            <a href="{{ $deployment ? route('deployments.show', $deployment) : route('deployments.index') }}" class="rounded-md px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700">Cancel</a>
            <button type="submit" :disabled="!items.length || !selected.length" class="rounded-md bg-brand-950 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-brand-900 disabled:opacity-50 dark:bg-brand-500 dark:hover:bg-brand-400">Check the firewalls</button>
        </div>
        <datalist id="pfc-ifaces"><option value="WAN"><option value="LAN"><option value="OPT1"><option value="OPT2"></datalist>
    </form>
</div>
</x-app-layout>

@php
    $input = 'block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 shadow-sm focus:border-brand-500 focus:ring-brand-500 text-sm';
    $label = 'block text-sm font-medium text-gray-700 dark:text-gray-300';
    $help = 'mt-1 text-xs text-gray-500 dark:text-gray-400';
@endphp
<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">Sign-in settings</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">How your own team signs in to {{ config('brand.name') }}.</p>
    </x-slot>

    <div class="py-8">
        <div class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
            @if (session('success'))
                <div class="p-4 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 dark:bg-emerald-900/30 dark:border-emerald-800 dark:text-emerald-300 text-sm" role="status">{{ session('success') }}</div>
            @endif
            @if ($errors->any())
                <div class="p-4 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 dark:bg-rose-900/30 dark:border-rose-800 dark:text-rose-300 text-sm" role="alert">
                    @foreach ($errors->all() as $message)<p>{{ $message }}</p>@endforeach
                </div>
            @endif

            <form method="POST" action="{{ route('system.signin.save') }}" class="space-y-6">
                @csrf
                <section class="bg-white dark:bg-gray-800 shadow-sm sm:rounded-lg p-6 space-y-5">
                    <div class="flex items-start gap-4">
                        <svg class="w-9 h-9 shrink-0" viewBox="0 0 23 23" aria-hidden="true"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>
                        <div class="flex-1">
                            <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">Sign in with Microsoft 365</h3>
                            <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                                Adds a "Sign in with Microsoft 365" button to the login page for your company (the MSP).
                                Everyone in the groups below can sign in and gets the <strong class="font-semibold text-gray-900 dark:text-gray-100">Administrator</strong> role for all companies.
                                Group membership is checked with Microsoft at every sign-in, so removing someone from the group stops them signing in.
                            </p>
                        </div>
                        @if ($ready)
                            <span class="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> On</span>
                        @else
                            <span class="shrink-0 inline-flex px-2.5 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">Off</span>
                        @endif
                    </div>

                    <label class="flex items-start gap-3">
                        <input type="checkbox" name="enabled" value="1" class="mt-0.5 rounded border-gray-300 dark:border-gray-700 dark:bg-gray-900 text-brand-600 focus:ring-brand-500" @checked(old('enabled', $enabled))>
                        <span><span class="{{ $label }}">Turn on Microsoft 365 sign-in</span><span class="{{ $help }} block">Email-and-password sign-in keeps working for everyone else.</span></span>
                    </label>

                    <div>
                        <label for="tenant_id" class="{{ $label }}">Your Microsoft 365 tenant ID</label>
                        <input id="tenant_id" name="tenant_id" value="{{ old('tenant_id', $tenantId) }}" class="{{ $input }} mt-1 font-mono" placeholder="0a1b2c3d-1234-4e5f-8a9b-0123456789ab" autocomplete="off" spellcheck="false">
                        <p class="{{ $help }}">Microsoft Entra admin center → Overview → Tenant ID. Only accounts from this tenant can sign in.</p>
                    </div>

                    <div>
                        <span class="{{ $label }}">Groups that may sign in</span>
                        @if ($tenantId)
                            <div class="mt-1">
                                @include('vpn.admin._ms-group-picker', [
                                    'pickerName' => 'ms_groups',
                                    'pickerSelected' => old('ms_groups') ? [] : $groups,
                                    'pickerUrl' => route('system.signin.groups'),
                                    'pickerPlaceholder' => 'Type to search your Microsoft 365 groups',
                                ])
                            </div>
                            <p class="{{ $help }}">Pick one or more groups. Nested groups count.</p>
                        @else
                            <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">Save your tenant ID first, then you can search and pick groups here.</p>
                            @foreach ($groups as $g)<input type="hidden" name="ms_groups[]" value="{{ $g['id'] }}">@endforeach
                        @endif
                    </div>
                </section>

                <section class="bg-white dark:bg-gray-800 shadow-sm sm:rounded-lg p-6 space-y-5" x-data="{ own: @js((bool) old('client_id', $clientId)) }">
                    <div>
                        <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">Microsoft app</h3>
                        <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                            @if ($vpnAppReady)
                                By default this uses the CFBTEL VPN Microsoft app (<span class="font-mono text-xs">{{ $vpnApp }}</span>).
                            @else
                                By default this uses the CFBTEL VPN Microsoft app, which is <span class="text-amber-700 dark:text-amber-300">not set up yet</span> (VPN Access → settings).
                            @endif
                            Either way, the app needs this redirect URI (Web platform) and the Microsoft Graph application permission <span class="font-mono text-xs">GroupMember.Read.All</span> with admin consent in your tenant.
                        </p>
                    </div>
                    <div x-data="{ copied: false }">
                        <span class="{{ $label }}">Redirect URI</span>
                        <div class="mt-1 flex gap-2">
                            <input readonly value="{{ $redirectUri }}" class="{{ $input }} font-mono text-xs bg-gray-50 dark:bg-gray-900/60" x-ref="uri" aria-label="Redirect URI">
                            <button type="button" class="shrink-0 px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700"
                                @click="navigator.clipboard.writeText($refs.uri.value); copied = true; setTimeout(() => copied = false, 1500)" x-text="copied ? 'Copied' : 'Copy'">Copy</button>
                        </div>
                    </div>
                    <label class="flex items-center gap-3">
                        <input type="checkbox" x-model="own" class="rounded border-gray-300 dark:border-gray-700 dark:bg-gray-900 text-brand-600 focus:ring-brand-500">
                        <span class="{{ $label }}">Use a separate Microsoft app for {{ config('brand.name') }} sign-in</span>
                    </label>
                    <div x-show="own" x-cloak class="grid sm:grid-cols-2 gap-5">
                        <div>
                            <label for="client_id" class="{{ $label }}">Application (client) ID</label>
                            <input id="client_id" name="client_id" :disabled="!own" value="{{ old('client_id', $clientId) }}" class="{{ $input }} mt-1 font-mono" autocomplete="off" spellcheck="false">
                        </div>
                        <div>
                            <label for="client_secret" class="{{ $label }}">Client secret</label>
                            <input id="client_secret" name="client_secret" type="password" :disabled="!own" class="{{ $input }} mt-1" autocomplete="new-password"
                                placeholder="{{ $hasSecret ? 'Saved. Type a new one to replace it.' : 'Not set' }}">
                            @if ($hasSecret)
                                <label class="mt-2 flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400"><input type="checkbox" name="clear_secret" value="1" class="rounded border-gray-300 text-brand-600"> Remove the saved secret</label>
                            @endif
                        </div>
                    </div>
                </section>

                <div class="flex items-center gap-4">
                    <button type="submit" class="inline-flex items-center px-4 py-2 rounded-md bg-brand-600 hover:bg-brand-700 text-white text-sm font-medium shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2">Save sign-in settings</button>
                </div>
            </form>
        </div>
    </div>
</x-app-layout>

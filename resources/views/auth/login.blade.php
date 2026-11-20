@php
    $microsoft = \App\Services\Auth\MspSignIn::enabled();
    $field = 'block w-full rounded-lg border-0 bg-white/[0.06] px-3.5 py-2.5 text-[0.95rem] text-slate-100 placeholder:text-slate-500 ring-1 ring-inset ring-white/15 focus:ring-2 focus:ring-inset focus:ring-brand-400 transition';
@endphp
<x-guest-layout>
    <h1 class="text-[1.65rem] font-semibold tracking-tight text-white">Sign in</h1>
    <p class="mt-1.5 text-sm text-slate-400">Every pfSense and OPNsense firewall you manage, in one place.</p>

    <x-auth-session-status class="mt-5 rounded-lg bg-emerald-500/10 ring-1 ring-emerald-400/25 px-3.5 py-2.5 !text-emerald-300" :status="session('status')" />

    @error('microsoft')
        <div class="mt-5 rounded-lg bg-rose-500/10 ring-1 ring-rose-400/25 px-3.5 py-2.5 text-sm text-rose-200" role="alert">{{ $message }}</div>
    @enderror

    @if ($microsoft)
        <a href="{{ route('login.microsoft') }}"
            class="mt-6 flex w-full items-center justify-center gap-3 rounded-lg bg-white px-4 py-3 text-[0.95rem] font-semibold text-slate-900 shadow-sm hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0B1D30] transition">
            <svg class="w-5 h-5" viewBox="0 0 23 23" aria-hidden="true"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>
            Sign in with Microsoft 365
        </a>
        <div class="my-6 flex items-center gap-3 text-xs uppercase tracking-wider text-slate-500" aria-hidden="true">
            <span class="h-px flex-1 bg-white/10"></span>or use your email<span class="h-px flex-1 bg-white/10"></span>
        </div>
    @endif

    <form method="POST" action="{{ route('login') }}" class="{{ $microsoft ? '' : 'mt-6' }} space-y-4" x-data="{ busy: false, show: false }" @submit="busy = true">
        @csrf
        <div>
            <label for="email" class="block text-sm font-medium text-slate-300">Email</label>
            <input id="email" class="{{ $field }} mt-1.5" type="email" name="email" value="{{ old('email') }}" required @unless($microsoft) autofocus @endunless autocomplete="username" inputmode="email">
            <x-input-error :messages="$errors->get('email')" class="mt-2 !text-rose-300" />
        </div>

        <div>
            <div class="flex items-center justify-between">
                <label for="password" class="block text-sm font-medium text-slate-300">Password</label>
                @if (Route::has('password.request'))
                    <a class="text-xs font-medium text-brand-300 hover:text-brand-200 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400" href="{{ route('password.request') }}">Forgot password?</a>
                @endif
            </div>
            <div class="relative mt-1.5">
                <input id="password" class="{{ $field }} pr-11" :type="show ? 'text' : 'password'" type="password" name="password" required autocomplete="current-password">
                <button type="button" @click="show = !show" class="absolute inset-y-0 right-0 px-3 text-slate-400 hover:text-slate-200 focus:outline-none focus-visible:text-white" :aria-label="show ? 'Hide password' : 'Show password'">
                    <svg x-show="!show" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                    <svg x-show="show" x-cloak class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88"/></svg>
                </button>
            </div>
            <x-input-error :messages="$errors->get('password')" class="mt-2 !text-rose-300" />
        </div>

        <label for="remember_me" class="inline-flex items-center gap-2.5 text-sm text-slate-400 select-none">
            <input id="remember_me" type="checkbox" name="remember" class="rounded border-white/20 bg-white/5 text-brand-500 focus:ring-brand-400 focus:ring-offset-0">
            Keep me signed in
        </label>

        <button type="submit" :disabled="busy"
            class="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-500 px-4 py-3 text-[0.95rem] font-semibold text-brand-950 shadow-[0_8px_24px_-8px_rgba(51,197,243,0.6)] hover:bg-brand-400 disabled:opacity-70 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-300 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0B1D30] transition">
            <svg x-show="busy" x-cloak class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-80" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/></svg>
            <span x-text="busy ? 'Signing in…' : 'Sign in'">Sign in</span>
        </button>

        <button type="submit" formaction="{{ route('login.magic') }}" formnovalidate
            class="w-full rounded-lg px-4 py-2.5 text-sm font-medium text-slate-300 ring-1 ring-inset ring-white/15 hover:bg-white/5 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400 transition">
            Email me a sign-in link instead
        </button>
    </form>
</x-guest-layout>

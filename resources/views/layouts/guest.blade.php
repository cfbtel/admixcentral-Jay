@php
    $settings = $settings ?? \App\Models\SystemSetting::pluck('value', 'key')->toArray();
    $favicon = $settings['icon_path'] ?? ($settings['favicon_path'] ?? asset('favicon.svg'));
    $version = \App\Support\ReleaseNotes::currentVersion();
    $isLogin = request()->routeIs('login');
@endphp
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" class="h-full dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="theme-color" content="#0E2238">
    <title>{{ $isLogin ? 'Sign in' : 'Account' }} · {{ config('brand.name') }}</title>
    <link rel="icon" href="{{ $favicon }}">
    <link rel="preconnect" href="https://fonts.bunny.net">
    <link href="https://fonts.bunny.net/css?family=inter:400,500,600,700,800&display=swap" rel="stylesheet" />
    <link rel="modulepreload" href="{{ asset('vendor/three/three.module.min.js') }}">
    <link rel="manifest" href="{{ route('manifest') }}">
    <script>
        window.AdmixConfig = { reverb: { key: "{{ env('VITE_REVERB_APP_KEY') }}", host: "{{ env('VITE_REVERB_HOST') }}", port: "{{ env('VITE_REVERB_PORT', 8080) }}", scheme: "{{ env('VITE_REVERB_SCHEME', 'http') }}" } };
    </script>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    <style>
        .pfc-bg { background: radial-gradient(1200px 700px at 28% 45%, #15406a 0%, #0E2238 55%, #081626 100%); }
        #pfc-scene { opacity: 0; transition: opacity 1.2s cubic-bezier(.16,1,.3,1); }
        .pfc-webgl-ready #pfc-scene { opacity: 1; }
        .pfc-fallback { display: none; }
        .pfc-no-webgl .pfc-fallback { display: flex; }
        .pfc-panel input:-webkit-autofill { -webkit-box-shadow: 0 0 0 40px #0B1D30 inset; -webkit-text-fill-color: #E2E8F0; caret-color: #E2E8F0; }
    </style>
</head>
<body class="h-full font-sans antialiased text-slate-200 pfc-bg overflow-x-hidden">
    {{-- 3D scene --}}
    <canvas id="pfc-scene" class="fixed inset-0 w-full h-full" aria-hidden="true"></canvas>
    <div class="pfc-fallback fixed inset-0 items-center justify-center lg:justify-start lg:pl-[18vw] pointer-events-none" aria-hidden="true">
        <img src="{{ asset('images/pfcentral-mark.svg') }}" alt="" class="w-48 h-48 opacity-90">
    </div>

    <div class="relative z-10 min-h-full flex flex-col">
        <header class="flex items-center justify-between px-5 sm:px-8 pt-5">
            <a href="{{ url('/') }}" class="rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400"><x-brand-logo size="h-9" /></a>
            @if ($isLogin)
                <a href="{{ route('system.signin') }}"
                    class="group inline-flex items-center gap-2 rounded-full px-3 py-2 text-sm text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 ring-1 ring-white/10 backdrop-blur-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400"
                    title="Sign-in settings (administrators)">
                    <svg class="w-5 h-5 transition-transform duration-500 group-hover:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                    </svg>
                    <span class="hidden sm:inline">Sign-in settings</span>
                </a>
            @endif
        </header>

        <main class="flex-1 flex items-end lg:items-center justify-center lg:justify-end px-4 sm:px-8 lg:pr-[8vw] pt-[38vh] lg:pt-0 pb-8">
            <div class="w-full max-w-[26rem]">
                <div class="pfc-panel dark relative rounded-2xl bg-[#0B1D30]/90 ring-1 ring-white/10 shadow-[0_30px_80px_-20px_rgba(0,0,0,0.65)] backdrop-blur-md p-7 sm:p-8">
                    {{ $slot }}
                </div>
            </div>
        </main>

        <footer class="px-5 sm:px-8 pb-5 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
            <p>&copy; {{ max(now()->year, config('brand.since')) }} {{ config('brand.owner') }}. All rights reserved.</p>
            <p class="tabular-nums">{{ config('brand.name') }} {{ $version }}</p>
        </footer>
    </div>

    <script type="module" src="{{ asset('js/login-scene.js') }}"></script>
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js').catch(function () {}); });
        }
    </script>
</body>
</html>

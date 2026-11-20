{{-- "What's new" window: opens once after each update, and again from the version link in the sidebar. --}}
@php
    $wnVersion = \App\Support\ReleaseNotes::currentVersion();
    $wnNotes = \App\Support\ReleaseNotes::for($wnVersion);
    $wnAuto = \App\Support\ReleaseNotes::unseenBy(auth()->user());
@endphp
@if ($wnNotes)
<div x-data="{
        open: @js($wnAuto),
        close() {
            this.open = false;
            fetch(@js(route('whats-new.seen')), { method: 'POST', headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name=csrf-token]').content, 'Accept': 'application/json' } });
        }
    }"
    @open-whats-new.window="open = true"
    @keydown.escape.window="open && close()"
    x-cloak>
    <div x-show="open" class="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="whats-new-title">
        <div x-show="open" x-transition.opacity.duration.200ms class="absolute inset-0 bg-brand-950/60 backdrop-blur-[2px]" @click="close()"></div>
        <div x-show="open"
            x-transition:enter="ease-out duration-300" x-transition:enter-start="opacity-0 translate-y-3 scale-[0.98]" x-transition:enter-end="opacity-100 translate-y-0 scale-100"
            x-transition:leave="ease-in duration-150" x-transition:leave-start="opacity-100" x-transition:leave-end="opacity-0"
            class="relative w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden rounded-2xl bg-white dark:bg-gray-900 shadow-[0_24px_60px_-12px_rgba(14,34,56,0.45)] ring-1 ring-black/5 dark:ring-white/10">
            <div class="relative px-6 pt-6 pb-5 bg-brand-950 text-white overflow-hidden">
                <div class="relative flex items-start gap-4">
                    <img src="{{ asset('images/pfcentral-mark.svg') }}" alt="" class="h-11 w-11 shrink-0" aria-hidden="true">
                    <div class="flex-1 min-w-0">
                        <h2 id="whats-new-title" class="text-xl font-semibold tracking-tight">{{ config('brand.name') }} has been updated</h2>
                        <p class="mt-1 text-sm text-brand-200">You're now on <span class="font-semibold text-white">{{ $wnVersion }}</span>. Here's what changed.</p>
                    </div>
                    <button type="button" @click="close()" class="p-1.5 -m-1.5 rounded-md text-brand-200 hover:text-white hover:bg-white/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400" aria-label="Close">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18 18 6M6 6l12 12"/></svg>
                    </button>
                </div>
            </div>
            <div class="flex-1 overflow-y-auto px-6 py-5 space-y-6">
                @foreach ($wnNotes as $section)
                    <section>
                        <h3 @class(['inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide',
                            'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' => $section['type'] === 'Added',
                            'bg-brand-50 text-brand-700 dark:bg-brand-900/40 dark:text-brand-200' => $section['type'] === 'Changed',
                            'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' => $section['type'] === 'Fixed',
                            'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300' => !in_array($section['type'], ['Added', 'Changed', 'Fixed'])])>{{ $section['type'] }}</h3>
                        <div class="release-notes mt-3 text-sm leading-relaxed text-gray-700 dark:text-gray-300">{!! $section['html'] !!}</div>
                    </section>
                @endforeach
            </div>
            <div class="px-6 py-4 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between gap-3">
                <a href="{{ route('whats-new') }}" class="text-sm font-medium text-brand-700 hover:text-brand-900 dark:text-brand-300 dark:hover:text-brand-200">All release notes</a>
                <button type="button" @click="close()" class="inline-flex items-center px-4 py-2 rounded-md bg-brand-600 hover:bg-brand-700 text-white text-sm font-medium shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900">Got it</button>
            </div>
        </div>
    </div>
</div>
@endif

{{-- PFCentral logo: the shield mark with the wordmark. tone="light" for dark backgrounds. --}}
@props(['tone' => 'light', 'wordmark' => true, 'size' => 'h-8'])
<span {{ $attributes->merge(['class' => 'inline-flex items-center gap-2.5 select-none']) }}>
    <img src="{{ asset('images/pfcentral-mark.svg') }}" alt="" class="{{ $size }} w-auto shrink-0" aria-hidden="true">
    @if ($wordmark)
        <span @class([
            'text-[1.2rem] leading-none tracking-tight whitespace-nowrap',
            'text-white' => $tone === 'light',
            'text-brand-950' => $tone === 'dark',
        ])><span class="font-extrabold">PF</span><span @class(['font-medium', 'text-brand-300' => $tone === 'light', 'text-brand-600' => $tone === 'dark'])>Central</span></span>
    @endif
</span>

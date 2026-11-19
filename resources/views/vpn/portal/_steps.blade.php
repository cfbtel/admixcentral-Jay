@php
    $apps = [
        'windows' => '<a href="https://www.wireguard.com/install/" rel="noopener">WireGuard for Windows</a>',
        'macos' => '<a href="https://apps.apple.com/app/wireguard/id1451685025" rel="noopener">WireGuard</a> from the Mac App Store',
        'iphone' => '<a href="https://apps.apple.com/app/wireguard/id1441195209" rel="noopener">WireGuard</a> from the App Store',
        'android' => '<a href="https://play.google.com/store/apps/details?id=com.wireguard.android" rel="noopener">WireGuard</a> from Google Play',
    ];
    $amnezia = 'Prefer AmneziaVPN? Install it from <a href="https://amnezia.org/en/downloads" rel="noopener">amnezia.org</a>, tap <em>+</em> and import the same file.';
@endphp
@if($p === 'windows' || $p === 'macos')
    <ol class="steps">
        <li>Install {!! $apps[$p] !!}.</li>
        <li>Click <strong>Download setup file</strong>.</li>
        <li>In WireGuard choose <em>Import tunnel(s) from file</em> and pick the <em>.conf</em> file{!! $p === 'macos' ? ', then click <em>Allow</em>' : '' !!}.</li>
        <li>Click <strong>Activate</strong>.</li>
    </ol>
@else
    <ol class="steps">
        <li>Install {!! $apps[$p] !!}.</li>
        <li><strong>Setting up from a computer screen?</strong> In WireGuard tap <em>+</em> → <em>{{ $p === 'iphone' ? 'Create from QR code' : 'Scan from QR code' }}</em> and scan the code.<br>
            <strong>On the phone itself?</strong> Tap <strong>Download setup file</strong>, then {!! $p === 'iphone' ? 'open it and share it to WireGuard' : 'tap <em>+</em> → <em>Import from file or archive</em>' !!}.</li>
        <li>Switch it on.</li>
    </ol>
@endif
<p class="small">{!! $amnezia !!}</p>

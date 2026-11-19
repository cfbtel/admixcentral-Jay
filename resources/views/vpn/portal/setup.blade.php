@extends('vpn.portal.layout')
@section('body')
    <h1>{{ $title }}</h1>
    @if(!empty($confirm))
        <p>This connects <strong>{{ $company->name }}</strong>'s Microsoft 365 to the CFBTEL staff VPN, so its people sign in to the VPN with their work account.</p>
        <p><strong>Sign in as a Global Administrator</strong> of {{ $company->name }}'s Microsoft 365 and accept the permissions. Then, in your Microsoft 365, AdmixCentral will:</p>
        <ul>
            <li>create an app named <strong>{{ $appName }}</strong> (only for your organization),</li>
            <li>give it permission to sign people in and to read your users and group memberships (to see who can use the VPN, to use groups such as "VPN", and to stop access when an account is disabled or leaves the group),</li>
            <li>create its secret (valid 2 years) and keep it encrypted at CFBTEL,</li>
            <li>then remove CFBTEL's setup access from your Microsoft 365.</li>
        </ul>
        @if($vc->hasOwnApp())
            <p class="small">{{ $company->name }} already has an app; running setup again gives it a new secret and fixes its permissions.</p>
        @endif
        <form method="POST" action="/vpn/setup">@csrf
            <input type="hidden" name="t" value="{{ $t }}">
            <button class="btn" type="submit">Continue to Microsoft</button>
        </form>
    @elseif(!empty($done))
        <p>✓ <strong>{{ $company->name }}</strong> is connected to Microsoft 365 <strong>{{ $vc->ms_tenant_name ?? $vc->ms_tenant_id }}</strong>.</p>
        <p>The app <strong>CFBTEL VPN</strong> was {{ $reused ? 'updated' : 'created' }} with its permissions approved. Its secret is valid until {{ $vc->ms_secret_expires_at?->format('F j, Y') }}.</p>
        @if($vc->domains())<p>Work email domains: {{ implode(', ', $vc->domains()) }}</p>@endif
        @if($cleaned)
            <p class="small">CFBTEL's setup access was removed from your Microsoft 365.</p>
        @else
            <p class="small">CFBTEL's setup access couldn't be removed automatically. You can delete the enterprise application "CFBTEL VPN Setup" in Entra if you like; nothing else needs it.</p>
        @endif
        <p class="small">It can take a few minutes before Microsoft accepts the new app everywhere. You can close this page.</p>
    @else
        <p>{{ $text }}</p>
        @if(!empty($retry))
            <form method="POST" action="/vpn/setup">@csrf<input type="hidden" name="t" value="{{ $retry }}"><button class="btn" type="submit">Try again</button></form>
        @endif
    @endif
@endsection

@extends('vpn.portal.layout')
@section('body')
    <h1>CFBTEL VPN</h1>
    <p>Sign in with your work Microsoft 365 account to set up the VPN on a computer or phone.</p>
    @if($error)<p class="error" role="alert">{{ $error }}</p>@endif
    <a class="btn ms" href="/vpn/login"><img src="/vpn-assets/microsoft.svg" alt="" width="18" height="18"> Sign in with Microsoft</a>
    <p class="small"><a href="/vpn/help">How it works</a></p>
@endsection

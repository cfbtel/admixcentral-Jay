{{-- Create (no $ag) or edit an access group. Uses $company, $sites, $users, $input, $btn2 from the page. --}}
@php
    $isOld = old('group_id') == ($ag?->id ?? 'new');
    $pickedSites = $isOld ? array_map('intval', (array) old('sites', [])) : ($ag?->sites->pluck('id')->all() ?? []);
    $pickedUsers = $isOld ? array_map('intval', (array) old('users', [])) : ($ag?->users->pluck('id')->all() ?? []);
    $everyone = $isOld ? (bool) old('everyone') : (bool) ($ag?->everyone);
@endphp
<form method="POST" action="{{ $ag ? route('vpn.access-groups.update', [$company, $ag]) : route('vpn.access-groups.store', $company) }}" class="mt-3 space-y-3 max-w-xl">@csrf
    <input type="hidden" name="group_id" value="{{ $ag?->id ?? 'new' }}">
    <div>
        <label class="block text-xs font-semibold mb-1">Group name</label>
        <input name="name" value="{{ $isOld ? old('name') : $ag?->name }}" maxlength="80" required placeholder="e.g. Office staff" class="w-full {{ $input }}">
    </div>
    <div>
        <p class="text-xs font-semibold mb-1">Firewalls in this group</p>
        @foreach($sites->values() as $gs)
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="sites[]" value="{{ $gs->id }}" @checked(in_array($gs->id, $pickedSites, true))> {{ $gs->firewall?->name }} @unless($gs->isReady())<span class="text-xs text-gray-500">({{ $gs->status }})</span>@endunless</label>
        @endforeach
    </div>
    <div>
        <p class="text-xs font-semibold mb-1">Members</p>
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="everyone" value="1" @checked($everyone)> Everyone with VPN access in this company</label>
        @if($users->isNotEmpty())
            <p class="text-xs text-gray-500 mt-2">…or these people:</p>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
                @foreach($users as $gu)
                    <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="users[]" value="{{ $gu->id }}" @checked(in_array($gu->id, $pickedUsers, true))> {{ $gu->name }} <span class="text-xs text-gray-500">{{ $gu->upn }}</span></label>
                @endforeach
            </div>
        @endif
        <p class="text-xs text-gray-500 mt-1">Microsoft 365 groups are linked after saving, with “Search groups”.</p>
    </div>
    <button class="{{ $btn2 }}">{{ $ag ? 'Save group' : 'Create group' }}</button>
</form>

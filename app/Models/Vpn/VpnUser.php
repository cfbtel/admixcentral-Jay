<?php

namespace App\Models\Vpn;

use App\Models\Company;
use Illuminate\Database\Eloquent\Model;

/** Someone a company admin gave VPN access, identified by their Microsoft 365 object id. */
class VpnUser extends Model
{
    protected $table = 'vpn_users';
    protected $fillable = ['company_id', 'ms_oid', 'upn', 'name', 'added_by', 'last_login_at'];
    protected $casts = ['last_login_at' => 'datetime'];

    public function company()
    {
        return $this->belongsTo(Company::class);
    }

    public function devices()
    {
        return $this->hasMany(VpnDevice::class);
    }

    public function activeDevices()
    {
        return $this->hasMany(VpnDevice::class)->whereNull('revoked_at');
    }
}

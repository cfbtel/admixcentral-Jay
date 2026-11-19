<?php

namespace App\Models\Vpn;

use App\Models\Company;
use Illuminate\Database\Eloquent\Model;

/** A company's Microsoft 365 tenant, connected through admin consent. */
class VpnCompany extends Model
{
    protected $table = 'vpn_companies';
    protected $fillable = ['company_id', 'ms_tenant_id', 'ms_tenant_name'];

    public function company()
    {
        return $this->belongsTo(Company::class);
    }

    public static function forCompany(Company $company): self
    {
        return static::firstOrCreate(['company_id' => $company->id]);
    }
}

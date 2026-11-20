<?php

namespace App\Models\Vpn;

use Illuminate\Database\Eloquent\Model;

/** A support ticket sent from the CFBTEL VPN Windows app. */
class VpnSupportReport extends Model
{
    protected $table = 'vpn_support_reports';
    protected $guarded = ['id'];
    protected $casts = ['emailed_at' => 'datetime'];

    public function reference(): string
    {
        return 'VPN-' . $this->id;
    }
}

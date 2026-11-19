<?php

namespace App\Models\Vpn;

use App\Models\Company;
use Illuminate\Database\Eloquent\Model;

/**
 * Someone a company admin gave VPN access:
 *  - "microsoft": identified by their Microsoft 365 object id (ms_oid), signs in with Microsoft;
 *  - "local": email (upn) and a password the person sets through an emailed invitation link.
 */
class VpnUser extends Model
{
    protected $table = 'vpn_users';
    protected $fillable = [
        'company_id', 'auth_type', 'ms_oid', 'upn', 'name', 'added_by', 'last_login_at',
        'password', 'invite_token_hash', 'invite_expires_at', 'invited_at', 'password_set_at', 'failed_logins', 'locked_until',
    ];
    protected $hidden = ['password', 'invite_token_hash'];
    protected $casts = [
        'last_login_at' => 'datetime',
        'invite_expires_at' => 'datetime',
        'invited_at' => 'datetime',
        'password_set_at' => 'datetime',
        'locked_until' => 'datetime',
    ];

    public function isLocal(): bool
    {
        return $this->auth_type === 'local';
    }

    /** "active", "invited" (no password yet) or "locked". */
    public function status(): string
    {
        if ($this->isLocal() && $this->locked_until && $this->locked_until->isFuture()) {
            return 'locked';
        }
        return $this->isLocal() && !$this->password ? 'invited' : 'active';
    }

    /** Ties a session to the current password: changing it signs out older sessions. */
    public function passwordVersion(): string
    {
        return substr(hash('sha256', (string) $this->password), 0, 20);
    }

    public static function findLocalByEmail(string $email): ?self
    {
        return static::where('auth_type', 'local')->where('upn', strtolower(trim($email)))->first();
    }

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

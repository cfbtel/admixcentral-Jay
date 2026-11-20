<?php

namespace App\Services\Vpn;

use App\Models\Company;
use App\Models\Vpn\VpnUser;
use Illuminate\Mail\Message;
use Illuminate\Support\Facades\Mail;

/**
 * VPN emails (invitations, password links), sent through the SMTP server set in VPN settings,
 * or through AdmixCentral's own mail setup when none is set.
 */
class VpnMailer
{
    private function mailer()
    {
        $host = VpnSettings::get('smtp_host');
        if (!$host) {
            return Mail::mailer();
        }
        $enc = VpnSettings::get('smtp_encryption', 'tls');
        return Mail::build([
            'transport' => 'smtp',
            'host' => $host,
            'port' => (int) VpnSettings::get('smtp_port', $enc === 'ssl' ? '465' : '587'),
            'scheme' => $enc === 'ssl' ? 'smtps' : 'smtp',
            'username' => VpnSettings::get('smtp_username'),
            'password' => VpnSettings::secret('smtp_password'),
            'timeout' => 20,
        ] + ($enc === 'none' ? ['auto_tls' => false] : []));
    }

    private function from(): array
    {
        return [
            VpnSettings::get('mail_from_address') ?: (config('mail.from.address') ?: 'no-reply@cfbtel.com'),
            VpnSettings::get('mail_from_name') ?: 'CFBTEL VPN',
        ];
    }

    /** Fill {placeholders}; values are plain text. */
    public static function render(string $template, array $vars): string
    {
        return strtr($template, collect($vars)->mapWithKeys(fn ($v, $k) => ['{' . $k . '}' => (string) $v])->all());
    }

    /** @param  array<string, string>  $attachments  file name => contents (plain text) */
    public function send(string $to, string $subject, string $text, ?string $replyTo = null, array $attachments = []): void
    {
        [$fromAddress, $fromName] = $this->from();
        $html = '<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#1f2937">'
            . preg_replace('#(https://[^\s<]+)#', '<a href="$1">$1</a>', nl2br(e($text)))
            . '</div>';
        $this->mailer()->send([], [], function (Message $m) use ($to, $subject, $text, $html, $fromAddress, $fromName, $replyTo, $attachments) {
            $m->to($to)->from($fromAddress, $fromName)->subject($subject)->text($text)->html($html);
            if ($replyTo) {
                $m->replyTo($replyTo);
            }
            foreach ($attachments as $name => $data) {
                $m->attachData($data, $name, ['mime' => 'text/plain']);
            }
        });
    }

    /** Invitation or new-password link for an email-and-password VPN account. */
    public function sendPasswordLink(VpnUser $user, string $link, \DateTimeInterface $expires, bool $reset = false): void
    {
        $company = Company::find($user->company_id);
        $vars = [
            'name' => $user->name,
            'email' => $user->upn,
            'company' => $company?->name ?? 'Your company',
            'link' => $link,
            'expires' => $expires->format('M j, Y g:i A T'),
            'portal' => VpnSettings::portalUrl('/vpn'),
        ];
        if ($reset) {
            $subject = self::render('Reset your {company} VPN password', $vars);
            $body = self::render("Hello {name},\n\nUse this link to set a new VPN password (it works until {expires}):\n{link}\n\nIf you didn't ask for this, you can ignore this email; your password stays the same.\n\nCFBTEL Support", $vars);
        } else {
            $subject = self::render(VpnSettings::inviteSubject(), $vars);
            $body = self::render(VpnSettings::inviteBody(), $vars);
            if (VpnMfa::required($user) && !VpnMfa::enabled($user)) {
                $body .= "\n\nTwo-factor sign-in is required: after you set your password you'll scan a QR code with an authenticator app on your phone, such as Google Authenticator or Microsoft Authenticator. Install one before you start.";
            }
        }
        $this->send($user->upn, $subject, $body);
    }
}

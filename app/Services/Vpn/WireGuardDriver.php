<?php

namespace App\Services\Vpn;

/**
 * What the VPN module needs from a firewall. One implementation per platform.
 *
 * Peers created here are named "cfbvpn-<device id>". Nothing else on the firewall is
 * removed or changed by these drivers apart from what setup() creates.
 */
interface WireGuardDriver
{
    /** @return array<int, array{id: string, descr: string, ipaddr: ?string, subnet: ?int}> */
    public function interfaces(): array;

    /** @return array<int, array{ref: string, name: string, listen_port: int, public_key: string}> */
    public function tunnels(): array;

    /**
     * Build the full remote-access setup and apply it.
     *
     * @param array{listen_port: int, subnet: string, lan: string, wan: string} $input
     * @return array{ref: string, name: string, public_key: string, gateway: string, log: string[]}
     */
    public function setup(array $input): array;

    /**
     * Every peer on the tunnel, managed or not (so addresses never collide).
     *
     * @return array<int, array{public_key: string, name: string, addresses: string[]}>
     */
    public function peers(string $tunnelRef): array;

    /** @param array{name: string, public_key: string, preshared_key: string, address: string, label: string} $peer */
    public function addPeer(string $tunnelRef, array $peer): void;

    /** Remove portal-managed peers (name starts with cfbvpn-) by public key and apply. Returns how many were removed. */
    public function removePeers(string $tunnelRef, array $publicKeys): int;
}

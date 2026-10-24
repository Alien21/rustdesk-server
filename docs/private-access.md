# Private relay access and guest invitations

This optional protocol requires the modified client on the owner's computers. Guests use an unmodified RustDesk client.

## Server configuration

Set the same independent access secret on both processes:

```sh
ACCESS_KEY=your-long-random-secret hbbs -r rustdesk.example.com
ACCESS_KEY=your-long-random-secret hbbr
```

The equivalent option is `--access-key SECRET`. Prefer the environment or a protected configuration file so the secret does not appear in the process command line. Share the signing key file `id_ed25519` between hbbs and hbbr. It stays on the servers; the access secret is a separate value.

Protected mode requires an explicit public relay address in hbbs `--relay-servers`. For a nondefault relay port include that normal public port in the address.

| Process | Default TCP port | Use |
| --- | --- | --- |
| hbbs | 21116 | Private control and normal public guest signaling |
| hbbr | 21117 | Private tunnel and normal public guest relay |

Private connections use an upgrade preamble on the existing TCP listeners. No additional private ports are opened. Existing WebSocket listeners remain guest entry points; owner control and tunnels require the existing TCP ports. The first version routes protected connections through the relay. The standard online-status query remains on hbbs TCP 21115.

Without `ACCESS_KEY` or `--access-key`, private access restrictions are disabled. The signed KX v1 greeting remains available on the existing rendezvous TCP port.

## Access rules

The public signing key never grants relay membership. Only a client authenticated with the private access secret can register an owned device or open an owned relay half. Devices also prove possession of their signing keys. Relay tickets bind the session UUID, target identity, device keys, roles, and admission deadline.

Unmodified clients may register passive targets through the original registration protocol. A PSK-authenticated controller can connect to those targets. Registration does not authorize an unmodified controller to connect to another unmodified target: hbbr always requires at least one authenticated PSK endpoint and a server-issued grant.

An owned client can enable **Allow clients without the private key to connect to this device**, which is off by default. Only that client's authenticated host registration may set the policy. With it enabled, unmodified controllers with the correct public server Key may connect to that device's real ID. Password, manual approval and existing security settings still apply. With it disabled, public controllers must use a valid invitation; owned PSK controllers keep their normal access. Invitations remain independent of this per-device switch.

The client creates a short alias such as:

```text
P-254785236@rustdesk.example.com?key=PUBLIC_SERVER_KEY
```

The key uses normal Base64 text expected by the RustDesk connection field. It is not URL-encoded. The access secret never appears in this value.

The `P-` namespace is reserved for invitations. The server checks generated aliases against stored device IDs and active invitations before reserving them. Each owned device has at most one current invitation; creating a new one replaces the previous one.

Validity is 1 to 1440 minutes. Expired or revoked invitations reject new admission. The owner's client validates both the alias and exact issued session UUID immediately before accepting a guest; normal password or manual approval still applies. Established sessions continue after expiration or revocation. Disconnecting or registering a new host-control connection revokes that device's previous invitations and pending grants. Existing relay bridges continue.

## Migration and online devices

The rendezvous TCP listener sends a signed KX v1 greeting for RustDesk 1.5.0 API clients. Install the updated private client (1.5.1) before this server: it verifies and consumes that greeting before its independent private handshake on the same port. The relay listener keeps its existing private handshake. API tokens require the encrypted rendezvous connection; JWT is not required and API login does not grant private membership or change invitation and public-access rules.

Update hbbs and hbbr together and preserve the original signing keys and peer database. The owner PCs need the modified client, including its local service, with the same **Private key** secret as `ACCESS_KEY`. The existing unmodified PCs can keep their ID server, relay and public Key settings. Their ID registration and heartbeat remain supported, and online responses combine live legacy peers with live authenticated control channels.

| Controller | Target | Admission |
| --- | --- | --- |
| PSK client | Registered legacy client | Allowed with target's normal password/approval |
| PSK client | PSK client | Allowed with target's normal password/approval |
| Public client | PSK client real ID | Only while that device allows public connections |
| Public client | PSK client P invitation | Only with a valid invitation |
| Public client | Legacy client | Rejected |

The public Key is not a secret. Any stock client can supply it, including through `ID@server?key=...`; the server cannot tell whether it was saved in the client's settings. The public-access switch therefore admits any caller with the correct server Key, subject to the target's password/approval, rather than identifying a list of known PCs. While the switch is enabled, real-ID access does not depend on an invitation's expiry. Leave it off for invitation-only public access.

Turning the switch off blocks new public admission, including pending requests. Already accepted sessions continue. Re-registering the host closes its previous invitation and pending grants as before. Private ownership is persisted in the existing peer database and cannot be replaced through legacy registration; converting a previously private ID to a legacy target requires deliberate server administration. Known legacy public keys are pinned in protected mode, so replacing a device's key also requires a deliberate reset.

Clipboard server-configuration import/export still transfers only host, relay, API and public Key. It does not export or import the private access secret, invitation settings or public-access policy.
## Transport

The private upgrade on the shared TCP ports uses a versioned, server-signed ephemeral X25519 exchange pinned to the public signing key. Directional authenticated encryption keys are derived from the shared key and complete exchange transcript. Encrypted records have monotonically increasing counters and a 64 KiB plaintext limit. Control JSON is also limited to 64 KiB. The access secret is sent only inside this permanent encrypted tunnel.

Inner RustDesk end-to-end encryption remains required for invitation sessions. Outer transport encryption is never reset after authentication. This protocol does not use TCP half-close; closing either direction closes the tunnel.

The servers bound authentication concurrency, message sizes, pending relays, invitation attempts, registered devices, and issued sessions. A guessed or copied short invitation ID still requires the owner's normal password or approval.

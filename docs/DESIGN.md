# Design

How the passkey class is put together, what it stores, and the security model behind it. For setup and configuration, see the [README](../README.md); for building and testing, [BUILDING.md](BUILDING.md). The [sequence diagrams](diagrams) show each flow end to end.

## Shape

The class, `com.pointbluetech.nam.login.passkey.PasskeyAuthClass`, is an Access Manager local authentication class. NAM runs it as a Method inside a Contract, alongside its own methods such as Name/Password. One class serves six modes, chosen by the `MODE` property on each Method:

| Mode | Runs after | Does |
|---|---|---|
| `MFA` | a method that identified the user | asks for one of the user's passkeys; enrolls the first one if they have none |
| `LOGIN` | nothing: it identifies the user | passkey alone (discoverable credentials) or user ID + passkey |
| `MANAGE` | a method that identified the user | lists, renames, removes and adds passkeys, after a fresh passkey proof |
| `RECOVERY` | a method that identified the user | takes a recovery code or helpdesk token, then a new passkey |
| `HELPDESK` | a method that identified the agent | lets an authorised agent issue a single-use token for a user |
| `UPGRADE` | a password method | lets the browser's password manager create a first passkey by itself; never blocks the sign-in |

WebAuthn itself (challenge generation, attestation and assertion verification, counters) is done by [Yubico's java-webauthn-server](https://github.com/Yubico/java-webauthn-server). It's bundled in the class's jar and relocated with its dependencies under `com.pointbluetech.shaded`, so it can't clash with libraries the Identity Server already has.

## Components

| Class | Role |
|---|---|
| `PasskeyAuthClass` | NAM entry point: picks the mode, routes each request, chooses the page |
| `PasskeyConfig` | parses and validates every property; an invalid configuration stops the class loading |
| `PasskeyService` | ceremonies for a known user: assertion, registration, rename, remove, limits |
| `PasskeyLogin`, `LoginCredentialRepository` | `LOGIN` mode: lookup by user handle or ID, and decoys for unknown IDs |
| `RelyingPartyFactory` | builds the Yubico relying party from the configuration |
| `CeremonyState` | per-sign-in state in NAM's session: pending challenges, gates passed, failures |
| `PasskeyStore`, `PasskeyRecord` | reading and writing passkeys on the user's attribute |
| `RecoveryStore` | recovery codes, helpdesk tokens and the recovery cool-down |
| `AccountRestrictions`, `EffectivePrivileges` | eDirectory account checks for `LOGIN` mode, where no password bind happens, and the proxy account's right to read what they check |
| `SsprResponses`, `SsprCrypt` | checking answers stored in SSPR's formats |
| `NmasChallengeProtocol`, `NmasCheck`, `NmasLogin` | checking answers stored in NMAS, through an NMAS login |
| `PasswordManagerSignals` | what a page passes to the user's password manager through the WebAuthn Signals API |
| `Notifier`, `NamMailSender` | notification and setup-code emails through NAM's email client |
| `logging.*` | routes everything, including the library's SLF4J output, to NAM's log, cleaned |

The JSPs in `src/main/webapp/jsp/` draw each page. They post back to the class, in the Identity Server's content frame or as a standalone page, the way NAM's own login pages do.

## State during a sign-in

Everything a sign-in needs between requests is kept in NAM's session, under keys scoped to the Method, so two passkey methods in one session don't share state:

- A WebAuthn request (challenge and options) is stored when a page is shown and removed when the response comes back, whatever the outcome. It's tied to the user's GUID and expires after `CHALLENGE_TTL_SEC`. A replayed or stale response finds nothing and fails.
- Which first-passkey checks were passed, the hash of an emailed setup code, and the count of wrong entries, which `MAX_FAILED` limits for the sign-in.
- A short-lived proof that the user verified a passkey, which unlocks the manage and helpdesk pages for `MANAGE_MAX_AUTH_AGE_SEC`. It serves only the method that made it: every passkey method forgets any proof when it starts and when it finishes. So a passkey sign-in, or a manage page left open, can't unlock a manage or helpdesk contract started afterwards in the same session, even though Access Manager asks only for the password again there.
- For the manage and helpdesk pages, a per-page action token, so a cross-site form can't trigger an action.

## Storage

### Passkeys

Each passkey is one value of `PASSKEY_LDAP_ATTRIBUTE`, `v1:` followed by compact JSON:

```
v1:{"id":"<credential ID, base64url>","pk":"<COSE public key, base64url>","sc":0,
    "uh":"<user handle, base64url>","nm":"MacBook Touch ID","aa":"<AAGUID>","tr":["internal","hybrid"],
    "be":true,"bs":true,"disc":true,"cr":"2026-11-01T14:03:00Z","lu":"2026-11-02T08:10:00Z"}
```

`rv: true` marks a passkey added during recovery, so the manage page can point it out. Values that aren't passkeys are left as they are when passkeys are written, so a shared attribute keeps its other values. Values in SSPR's response format are recognised and skipped.

- **User handle:** the UTF-8 bytes of the user's directory GUID, as NAM reports it. It's stable, carries no personal data, and lets `LOGIN` mode find the user directly by GUID.
- **Counters:** the sign counter and last-used time are written only when the counter rises, or when the last-used time is older than `LAST_USED_WRITE_INTERVAL`. Synced passkeys always report 0, so this avoids a directory write on every sign-in. A non-zero counter that goes backwards is refused.
- **Access:** the user store's proxy account needs read and write on the attribute, and the right to add the auxiliary class if `PASSKEY_AUX_CLASS` is set. Users must not be able to write it themselves, or they could plant keys through LDAP.
- **Concurrency:** every write is one LDAP modify that removes exactly the values that went and adds the new ones. eDirectory applies it whole or not at all, and refuses it if a value to remove is already gone or one to add already exists. So a recovery code or helpdesk token used by two requests at once works for only one of them, and a write never brings back a value someone else removed meanwhile, such as a used code in a shared attribute. Other writes start again from a fresh read when that happens. NAM's own modify calls replace the whole attribute, so for these writes the class borrows one admin connection from NAM's own pool, for the replica the session reads from, and hands it straight back; it keeps no connections and retries nothing, and a failed write fails the request. Requests that reach different replicas at the same moment are only as consistent as eDirectory's replication.

### Recovery codes and helpdesk tokens

Codes and tokens are 16 characters of base32, 80 random bits, shown once. Only an HMAC-SHA256 is stored, keyed with `RECOVERY_PEPPER` and bound to the user's GUID, so a stored value is useless copied to another account and can't be checked without the pepper:

| Value | Meaning |
|---|---|
| `rc1:<hmac>` | an unused recovery code; removed when used |
| `et1:<hmac>:<expiry ms>:<wrong entries>` | a helpdesk token; removed when used, expired, or after `MAX_FAILED` wrong entries |
| `rr1:<epoch ms>` | when the account was last recovered, for `RECOVERY_COOLDOWN_SEC` |

The pepper lives in NAM's configuration store. Keeping that store separate from the user store means a leak of the user store alone exposes nothing checkable.

### Schema

`schema/edir-passkey.ldif` adds `pbtPasskeyCredential`, `pbtPasskeyRecovery` and `pbtPasskeyEnrollToken` to eDirectory, with the `pbtPasskeyUser` auxiliary class. Until a site applies it, the default `carLicense` works without a schema change, with the caveat about NAM's TOTP class in the README.

## Passwordless sign-in

`LOGIN` mode identifies the user itself, so it has more to check than the other modes:

- **Lookup:** a passkey alone returns its user handle, and the class finds the user by GUID across the method's user stores. With an ID first, it looks the ID up and asks only for that user's passkeys.
- **Unknown IDs:** an unknown ID, or one with no passkeys, gets a decoy credential, so the page doesn't reveal which accounts exist. The decoy comes from an HMAC of the ID, keyed from `RECOVERY_PEPPER`, so it's the same on every node and after a restart, as a real user's credentials would be. Without a pepper the key is per JVM, and the class warns at startup. Each decoy takes the credential ID length and transports of one of a few common kinds of passkey, chosen by the ID, so it doesn't stand out by shape. A real user's answer does the same directory work as a decoy's: one search for the ID, then one read, of their passkeys, which the challenge reuses.
- **Account state:** no password is checked, so the directory never refuses a bind. The class reads `loginDisabled`, the intruder lockout and `loginExpirationTime` itself, then runs NAM's login policy check, and refuses unless both pass. An attribute with no value doesn't restrict the account, and a value it can't understand refuses. eDirectory returns an attribute the proxy account may not read as if it had none, so the administrator must grant the proxy account read access to these attributes. With `ACCOUNT_CHECK=verify-rights` the class confirms that right with eDirectory's Get Effective Privileges extended operation before trusting an empty value, caching a confirmed answer per container for an hour, and refuses without it. `ACCOUNT_CHECK=off` leaves the account state to NAM's login policy check alone.
- **User verification** is always required.

Known gaps, which only tell whether an ID has a passkey: a user with several passkeys lists that many, while a decoy always lists one; decoys take common shapes, so someone who knows which authenticators your users have could still guess from the mix, though not from one look at a credential; the directory work is matched, but its time isn't measured to the millisecond; and when the directory is failing, an unknown ID can see "please try again" where a known one wouldn't. No decoy can be perfect while the browser must be given real credential IDs. `ALLOW_IDENTIFIER_FIRST=false` removes all of these: signing in with the passkey alone sends no credential IDs at all.

## The first passkey

By default, a password is enough to add a user's first passkey, which is also enough for an attacker holding a stolen password. `ENROLL_GATES` adds checks before that first passkey: an emailed code, a helpdesk token, or the user's security questions. The README sets out the trade-offs.

**Automatic upgrade** (`UPGRADE`) is the password-only case with no page at all. The browser creates the passkey through WebAuthn conditional create, without user presence or verification, so the registration is verified with the library's conditional-create option, and only in this mode. Because nothing is asked, the mode refuses `ENROLL_GATES` and `ALLOWED_AAGUIDS` at load time. It creates a passkey only for a user with none, checked again when the response arrives. The new passkey doesn't count as a passkey proof for the manage or helpdesk pages. Any failure, including a directory error, finishes the method so the password sign-in goes ahead.

**SSPR answers** are read from the attribute SSPR writes and checked locally, in every format SSPR uses: TEXT, MD5, SHA1, the salted SHA variants, PBKDF2 with SHA-1, SHA-256 and SHA-512, BCRYPT and SCRYPT. The checks were written from the storage format and are tested against records written by SSPR's own library. BCRYPT and SCRYPT use the BouncyCastle library Access Manager already ships.

**NMAS answers** can't be read, only tested. The class runs an NMAS login as the user, a SASL `NMAS_LOGIN` bind, against a replica of the user's own eDirectory store over Access Manager's trusted TLS connection, with the Challenge Response method run by the class itself. eDirectory picks the questions partway through that login, so the login waits on its own thread while the page shows them; waiting logins are capped and time out. Only an HMAC of each lower-cased answer is sent. The NMAS client and LDAP libraries are the ones Access Manager ships, so nothing extra is installed.

## Security model

What each part relies on, and the checks behind it:

- **Relying party:** `RP_ID` and `ORIGINS` are explicit and validated; origins must match exactly, with port and subdomain matching off. The library checks origin, RP ID hash, challenge, flags and signature.
- **Challenges** are single-use, bound to the session and the user, and time-limited.
- **`MFA` mode:** the passkey's user handle must be the user the earlier method identified.
- **Registration flags:** creating a passkey needs user verification, except in `UPGRADE` mode, where the browser creates it without the user present or verified. Only that mode accepts such a registration, and only for a user with no passkey.
- **Registration:** the creation options list the user's existing passkeys, so an authenticator that already holds one refuses to make another rather than silently replacing it.
- **Management:** a user with passkeys must prove one, with user verification, before the manage page shows anything; a password alone never adds or removes a passkey on such an account.
- **Recovery:** codes and tokens are single-use and stored only as HMACs. New codes are held back after a recovery for `RECOVERY_COOLDOWN_SEC`, so someone who recovered an account first can't lock its owner out; with `NOTIFY_EMAIL`, the owner is emailed.
- **Helpdesk:** agents are checked against the group on every request, must prove their own passkey and confirm each identity check, and can't issue a token for themselves. Every issue is logged.
- **Authenticator allow-list:** an AAGUID counts only with attestation that chains to a configured vendor root.
- **Password manager signals** (`SIGNAL_PASSWORD_MANAGERS`): a page passes the list of a user's passkeys only from a fresh, successful read, never an empty one, and only after the user proved a passkey from that list in this sign-in. The passkey-only page reports a passkey as unknown only when its user was found with other passkeys and not this one. Anything uncertain sends nothing, so a working passkey is never dropped.
- **Pages:** every value a page prints is HTML- or JavaScript-escaped, and the WebAuthn options JSON is escaped for its `<script>` block. Every passkey page is sent with `Cache-Control: no-store`, since each holds a live challenge, action token, CSRF token or codes, so neither the browser nor a cache in between keeps it.
- **Logging:** no challenge, signature, code, token, answer, email address or the pepper is logged. Every message is cleaned of control characters and markup, so text the browser sent can't forge a log line.

Each point has a unit test, and the browser tests cover the flows end to end. What the class can't control: other contracts on the Identity Server stay reachable, so a password-only contract still works unless it's removed or applications require a higher authentication level; and with the default settings, or with `UPGRADE`, a password alone can enroll a first passkey.

## Roadmap

- Active Directory user stores: test the existing AD code paths, and add AD schema guidance
- Translations of the pages and emails
- End-to-end tests for the helpdesk first-passkey check and the authenticator allow-list
- Testing password manager sync with Chrome and Google Password Manager, and in other browsers as they add the Signals API
- Testing the automatic upgrade in Safari and Chrome, including which saved logins browsers match to the passkey's user name
- Testing on more authenticators: Windows Hello, Android, password managers, hardware security keys, and phone sign-in by QR code
- Testing on multi-node clusters and containers

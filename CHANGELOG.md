# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org).

## Unreleased

- `RECOVERY_CODES=false` turns recovery codes off: none are offered after the first passkey or on the manage page, any issued before are refused, and the recovery page asks only for a helpdesk code. Helpdesk tokens keep working.
- Docs: screenshots of the sign-in, manage, recovery and helpdesk pages, taken by `npm run screenshots` in `e2e/`

## 0.1.0-beta.3

Upgrading from 0.1.0-beta.2: replace the jar and every JSP as in [INSTALL.md](INSTALL.md); only `passkey_manage.jsp` changed, and there are no new pages. Nothing needs configuring. Two changes in behaviour to know about: a contract that runs two passkey methods one after the other now asks for the passkey in each, and every identifier-first decoy changes once.

### Security fixes

- **Fix:** the creation options now list the user's existing passkeys. Before, the list was always empty, so an authenticator that already held one of the user's passkeys could make another, or silently replace it and leave a passkey on the server that no longer worked.
- **Fix:** a recovery code or helpdesk token used by two requests at the same moment works for only one. Every write is now one LDAP modify that changes only the values that differ and fails if the attribute changed since it was read, so a write can no longer bring back a value someone else removed meanwhile, such as a used recovery code in a shared attribute. Wrong helpdesk-token entries made at the same moment are each counted.
- **Fix:** a passkey proof unlocks the manage and helpdesk pages only for the method that made it; each passkey method forgets any proof when it starts and when it finishes. Before, a passkey sign-in, or a manage page left open, let a manage or helpdesk contract started afterwards in the same browser open after only the password.
- Every passkey page is sent with `Cache-Control: no-store` and `Pragma: no-cache`, not only the pages showing recovery codes and helpdesk tokens. The others hold a live challenge or form tokens, and Access Manager doesn't send these headers for them in every setup.

### Changes

- `ACCOUNT_CHECK` for passkey-only sign-in (`LOGIN` mode): how the class checks eDirectory account restrictions itself. `attributes` (the default, as before) reads `loginDisabled`, the intruder lockout and `loginExpirationTime`. `verify-rights` also confirms with eDirectory that the user store's proxy account may read them, since eDirectory returns an attribute the proxy can't read as if it had no value, and refuses the sign-in without that right. `off` leaves the account state to NAM's login policy check alone.
- Identifier-first decoys look more like real passkeys: each takes the credential ID length and transports of a common kind of passkey, where before every decoy was 32 bytes with the same transports. A real user's answer no longer takes an extra directory search, so it isn't slower than a decoy's. Upgrading changes every decoy once.
- The manage page says "Synced" only for a passkey its provider reports as backed up now, "Not synced yet" for one that can be but isn't yet, and "This device only" for one that can't be. Before, it said "Synced" for any passkey that could be backed up.
- Passkeys are listed oldest first, since the directory keeps values in no particular order.

### Project

- Continuous integration: GitHub Actions runs the unit tests on Java 11 and 21 and type-checks the browser tests, using a `ci` Maven profile that builds without Access Manager's jars; Dependabot keeps the dependencies current.
- Docs: the proxy account must be able to read those attributes, and that's the administrator's to grant; the design notes no longer claim an unreadable attribute refuses by itself.

## 0.1.0-beta.2

Upgrading from 0.1.0-beta.1: replace the jar and every JSP as in [INSTALL.md](INSTALL.md), and add the new `passkey_upgrade.jsp` (with the Advanced File Configurator, as a file of its own). Nothing else changes: both new features stay off until you configure them, and stored passkeys aren't touched.

- Optional automatic passkey upgrade (`MODE=UPGRADE`): after a user signs in with a password their browser's password manager filled in, the browser may create a passkey by itself, with no prompt (WebAuthn conditional create). Only for users with no passkey yet. It never stops the password sign-in. New page `passkey_upgrade.jsp`.
- Optional password manager sync (`SIGNAL_PASSWORD_MANAGERS=true`): through the WebAuthn Signals API, the manage page tells the user's password manager which passkeys they still have and which one they just removed, and the passkey-only page tells it to forget a passkey this site no longer has. Only what the class is sure of is sent.
- Cookbook for YubiKey-only passkeys when moving from certificate sign-in ([docs/cookbooks/yubikey-only.md](docs/cookbooks/yubikey-only.md))
- Sequence diagrams for the automatic upgrade, password manager sync, and registering an approved security key

## 0.1.0-beta.1

First public beta, for OpenText Access Manager 5.1.3 / 26.2 with eDirectory. An independent project, not an OpenText product or supported by OpenText. See the README's [Status](README.md#status) for what has and hasn't been tested yet.

- Five modes: password + passkey (`MFA`), passkey-only sign-in by passkey alone or user ID + passkey (`LOGIN`), self-service management (`MANAGE`), account recovery (`RECOVERY`) and helpdesk tokens (`HELPDESK`)
- Several passkeys per user, stored on a directory attribute, with an optional eDirectory schema extension
- Optional checks before a user's first passkey: an emailed code, a helpdesk token, or SSPR or NMAS security questions
- Single-use recovery codes and helpdesk tokens, stored only as peppered HMACs, with an optional cool-down after each recovery
- Optional allow-list of authenticator models, checked against vendor attestation
- Notification emails through NAM's own email configuration
- A fallback link from the passwordless page, to NAM's default contract or a contract you choose
- Release bundle with a single-node installer, and instructions for the Advanced File Configurator, Docker and Kubernetes

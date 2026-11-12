# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org).

## Unreleased

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

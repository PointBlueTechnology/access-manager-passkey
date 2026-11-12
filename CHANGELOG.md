# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org).

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

# Security policy

This class handles sign-in for an identity provider, so we take reports seriously.

## Reporting a vulnerability

Please **don't** open a public issue. Report it privately through GitHub instead: on this repository, go to **Security > Report a vulnerability**. Include the version, your Access Manager version and user store, what you found, and how to reproduce it.

We'll acknowledge the report within a few working days, keep you informed, and credit you in the release notes if you'd like.

## Supported versions

| Version | Supported |
|---|---|
| Latest release (currently the 0.1.0 betas) | Yes |
| Anything older | No: please upgrade first |

## Scope

In scope: this repository's code, pages, installer and schema. Out of scope: Access Manager itself, eDirectory, SSPR and browsers. Report problems in those to their vendors. This project isn't an OpenText product, so OpenText can't take reports about it. The design and the protections the class relies on are described in [docs/DESIGN.md](docs/DESIGN.md#security-model).

# Building and testing

This covers building the passkey class from source, running its tests, and the project layout. To install a release on an Identity Server, see [INSTALL.md](../INSTALL.md). To configure it, see the [README](../README.md).

## Requirements

- Maven 3.9 or newer
- JDK 11 or newer (the build targets Java 11 bytecode)
- An Access Manager 5.1.3 / 26.2 Identity Server to copy jars from
- For the browser tests: Node.js, Google Chrome, and a test Identity Server

## Access Manager jars

The class compiles against jars that ship with the Identity Server. They're OpenText's, so they aren't in this repository and must not be redistributed. Copy them from your own server into `reference/`, which is gitignored:

From `/opt/novell/nam/idp/webapps/nidp/WEB-INF/lib`:

- `nidp.jar`
- `NAMCommon.jar`
- `jcc.jar`
- `nmasclient.jar`
- `ldap.jar`
- `nam-email-client-core.jar`
- `nam-email-client-config-nidp.jar`
- `nam-email-client-config-xsd.jar`
- `mail-1.5.0-b01.jar`

Then install them into your local Maven repository as `provided` dependencies:

```bash
scripts/install-nam-jars.sh
```

Run it again after copying jars from a different Identity Server version, and set `NAM_VERSION` to match `nam.version` in `pom.xml`.

## Build

```bash
mvn package
```

This runs the unit tests and produces:

- `target/nam-passkey-auth-<version>.jar`, the class as a single jar. The Yubico WebAuthn library and its dependencies (Jackson, Guava, CBOR, HttpClient 5, SLF4J) are bundled and relocated under `com.pointbluetech.shaded`, so they never conflict with the Identity Server's own copies. None of the Access Manager jars are included. Ignore `target/original-*.jar`, the unshaded jar.
- `target/nam-passkey-auth-<version>-bundle.zip` and `.tar.gz`, the release bundle: the jar, the JSPs, the schema LDIF, `install.sh`, INSTALL.md, `VERSION`, `LICENSE` and `THIRD-PARTY-NOTICES.txt`.

## Unit tests

```bash
mvn test
```

The unit tests need no server. They run real WebAuthn ceremonies against a software authenticator, including packed attestation for the authenticator allow-list. They check:

- the challenge, replay and sign-counter rules
- configuration validation
- recovery codes and helpdesk tokens
- notification emails
- SSPR answer formats, using records written by SSPR's own library (ldapchai, test scope only)
- the NMAS challenge-response exchange, against a fake server

## Deploying to a test node

```bash
scripts/deploy-test.sh root@idp.example.com
```

It copies the jar and JSPs from `target/` and `src/` straight into the node's webapp and restarts the Identity Server. Use it only on a test node; production nodes should get the release bundle through INSTALL.md.

## Browser tests

`e2e/` holds Playwright tests that drive a test Identity Server through each flow. Chrome's virtual authenticator acts as the passkey, so no device is needed. The tests check what each page shows, and read the Identity Server's log over ssh to check what the class logged.

They cover:

- signing in with only a passkey, by button and from autofill, and refusing a disabled account even with its passkey
- the "Use another way to sign in" fallback, and `PASSKEY_ONLY` hiding it
- the first-passkey checks: an emailed code, and SSPR or NMAS security questions
- helpdesk access, its required checks, refusing a token for the agent's own account, and issuing one
- recovering with a helpdesk token or a recovery code, each working only once, and creating new codes
- ending an attempt after `MAX_FAILED` wrong codes
- that no code, token or test password reaches the log or an email

Touch ID and Safari autofill are tested by hand.

### Setup

1. Create test accounts, for example `pktest-agent` in the helpdesk group and `pktest-user` outside it. They need no passkeys: the tests give each one its own software passkey through the manage contract, and replace `pktest-user`'s recovery codes on every run. Don't use real accounts.
2. Copy `e2e/.env.example` to `e2e/.env`. Set `E2E_BASE_URL` and `E2E_SSH` for your test server, fill in the IDs and passwords, and change the contract IDs if yours differ. These are the IDs on each contract's Authentication Card tab (the `main.jsp?id=` value, not the contract's name or URI). Use passwords long enough that they can't match ordinary log text.
3. `cd e2e && npm install`. The tests use the installed Google Chrome.
4. Set up key-based ssh from this machine to the Identity Server, which `scripts/deploy-test.sh` needs too.

Each optional test is skipped until its settings are in `.env`:

- **Disabled account:** set `E2E_DISABLED_ID`. A disabled account can't sign in to get a passkey, so the first time, enable it, set `E2E_DISABLED_PASSWORD`, run `npm test -- -g "software passkey"`, then disable it again.
- **Passkey-only fallback:** set `FALLBACK_CONTRACT_URL` on the passkey class, so the usual `LOGIN` contract shows "Use another way to sign in". Add a second `LOGIN` method with `PASSKEY_ONLY=true` in its own contract, and set `E2E_CONTRACT_PASSKEY_ONLY` to that contract's ID. The test signs in to nothing.
- **Emailed first-passkey code:** create a contract of Name/Password, then a `MANAGE` method with `ENROLL_GATES=email`, and an account with no passkeys whose mail value reaches [MailCatcher](https://mailcatcher.me). Set `E2E_CONTRACT_GATED`, `E2E_ENROLL_ID`, `E2E_ENROLL_PASSWORD` and `E2E_ENROLL_MAIL`. The test removes the passkey it makes, so the account is ready for the next run.
- **SSPR security questions:** load `e2e/fixtures/sspr-responses.ldif` onto the same account. It holds SSPR-format test answers made with SSPR's own library; change its DN and attribute if yours differ. Create a contract of Name/Password, then a `MANAGE` method with `ENROLL_GATES=questions` and a matching `QUESTIONS_SSPR_ATTRIBUTE`, and set `E2E_CONTRACT_QUESTIONS`.
- **NMAS security questions:** give the same account the same four questions and answers in NMAS, through SSPR set to store answers in NMAS or through iManager. Add a second contract whose method also has `QUESTIONS_STORE=nmas`, and set `E2E_CONTRACT_QUESTIONS_NMAS`. The tree needs a `Challenge Response` login sequence, or set `QUESTIONS_NMAS_SEQUENCE` to yours.
- **Recovery cool-down:** set `RECOVERY_COOLDOWN_SEC` on the class to something short, such as `30`, and `E2E_RECOVERY_COOLDOWN_SEC` to the same value. The tests then wait it out after each recovery.
- **Notification emails:** set `NOTIFY_EMAIL=true` on the class, `E2E_USER_MAIL` to an address that reaches MailCatcher, and `E2E_MAILCATCHER_URL` if it isn't on `localhost:1080`.

### Running

```bash
cd e2e && npm test
```

Use `npm run test:headed` to watch, and `npm run check` to type-check the tests.

Each software passkey's private key is kept in `e2e/.state/`, so later runs sign in with it. If an account's passkeys are cleared on the server, delete its file there. If the file is lost while the account still has passkeys, clear the account's passkey values so it can enroll again.

`.env`, `.state/` and the test output are gitignored. The tests record no traces, screenshots or videos, because pages show codes and the password fields get filled in.

If NAM's pooled user-store connections time out while idle, the first search after a quiet spell can fail and the stock password page says "Login failed". The test driver retries the password page once and notes it in the report.

## Diagrams

The sequence diagrams in [docs/diagrams](diagrams) are drawn from one source file, `docs/diagrams/passkey-flows.flow`, with FlowDiagram. After changing it, render the SVGs again:

```bash
scripts/render-diagrams.sh
```

It needs FlowDiagram's command-line tool, `fdiag`, on the `PATH`.

## Layout

```
src/main/java/com/pointbluetech/nam/login/passkey/           the authentication class, configuration and ceremonies
src/main/java/com/pointbluetech/nam/login/passkey/logging/   SLF4J to NIDPLog bridge, log cleaning
src/main/java/org/slf4j/impl/                                SLF4J 1.7 binding (relocated when shaded)
src/main/resources/                                          messages, authenticator names, third-party notices
src/main/webapp/jsp/                                         sign-in, registration, manage, recovery and helpdesk pages
src/assembly/                                                release bundle definition
src/test/                                                    unit tests and the software authenticator
schema/                                                      eDirectory schema extension
scripts/install-nam-jars.sh                                  installs the reference/ jars into ~/.m2
scripts/deploy-test.sh                                       copies the jar and JSPs to a test node and restarts it
scripts/install.sh                                           single-node installer shipped in the release bundle
scripts/render-diagrams.sh                                   renders the sequence diagrams to SVG
e2e/                                                         Playwright browser tests
docs/                                                        this guide, the design notes and the diagrams
reference/                                                   your Access Manager jars (gitignored, never commit)
```

How the class is put together, what it stores, and its security model are in [DESIGN.md](DESIGN.md).

# Cookbook: YubiKey-only passkeys, moving from certificate sign-in

This cookbook sets up passkeys so that only approved YubiKey models can be registered, for example the YubiKey 5C Nano FIPS. It's written for a site that signs users in with X.509 certificates today and wants to move to passkeys without weakening anything along the way.

> **Status:** the authenticator allow-list is unit-tested but hasn't yet been tested end to end on a live Identity Server (see the README's [Status](../../README.md#status)). Run this whole cookbook on a test Identity Server first.

## What you end up with

- Users enroll a YubiKey only after signing in with their existing certificate. A password alone never adds a passkey.
- Only the YubiKey models you list can be registered. The check uses the key's attestation, which chains to Yubico's root certificate, so software can't pretend to be a YubiKey.
- Every sign-in with a passkey needs the YubiKey's PIN as well as a touch.
- Users can then sign in with the YubiKey alone, and you retire certificate sign-in when everyone has enrolled.

## 1. Find out what you're allowing

You need two things: Yubico's attestation root certificates, and the AAGUID of each YubiKey model you'll accept.

**Root certificates.** Download Yubico's FIDO attestation roots from [developers.yubico.com/PKI](https://developers.yubico.com/PKI/). Older keys chain to *Yubico FIDO Root CA Serial 457200631*. Keys with firmware 5.7 or later chain to Yubico's newer *Yubico Attestation Root 1*. If your fleet mixes firmware versions, use both. Note what `ykman info` reports as each key's firmware.

**AAGUIDs.** An AAGUID names a model and firmware family, not a single key. FIPS and non-FIPS models have different AAGUIDs, and so do firmware generations of the same model. So don't copy an AAGUID from a web page. Read it from the keys you actually issue (step 3), or from the FIDO Alliance Metadata Service entry for that exact model.

## 2. Prepare the keys

On each YubiKey, before it's handed out:

- **Set a FIDO2 PIN** (`ykman fido access change-pin`). A FIPS YubiKey is in its FIPS-approved mode only once a PIN is set. The class also needs the PIN, because `LOGIN` mode requires user verification.
- **Check the firmware** with `ykman info`, so you know which root certificate and AAGUID it uses.
- **Keep room for the passkey.** It's stored on the key itself (a discoverable credential), and YubiKeys hold a limited number of them: 25 on firmware 5.4 and earlier, 100 on 5.7 and later. `ykman fido credentials list` shows what's there.

## 3. Read the AAGUID from a real key

The class logs the AAGUID of every authenticator it refuses, so you can get the exact value from a key you've issued:

1. On a test method, set `ALLOWED_AAGUIDS` to any placeholder that will never match, such as `00000000-0000-0000-0000-000000000001`, and set `ATTESTATION_TRUST_ROOTS` to Yubico's roots.
2. Try to register the YubiKey. It will be refused.
3. Look in the Identity Server log for the refusal:

   ```
   [Passkey] Passkey registration failed for <user>: Refused authenticator <aaguid> (<model name, if known>): not in ALLOWED_AAGUIDS
   ```

   - **`not in ALLOWED_AAGUIDS`:** the attestation chained to your roots. The hex value is the AAGUID to allow.
   - **`isn't from a trusted root`:** the roots don't match this key. Check its firmware against step 1.

Do this for every model and firmware family you'll issue.

## 4. Configure the class

On the **Class** (Identity Servers > Edit > Local > Classes), so every method agrees:

| Property | Value |
|---|---|
| `RP_ID`, `ORIGINS` | as in the README |
| `ALLOWED_AAGUIDS` | the AAGUIDs from step 3, separated by commas |
| `ATTESTATION_TRUST_ROOTS` | Yubico's root certificates as PEM, one after another. Line breaks are optional |
| `USER_VERIFICATION` | `required`, so a PIN is needed for every sign-in, including `MFA` |
| `AUTHENTICATOR_ATTACHMENT` | `cross-platform`, so browsers offer the security key straight away and don't suggest Touch ID or Windows Hello |
| `RESIDENT_KEY` | `required` (the default), so users can sign in with the key alone |
| `PASSKEY_LDAP_ATTRIBUTE` | the dedicated attribute from the [schema](../../README.md#schema), not `carLicense` |
| `RECOVERY_PEPPER` | 64 hex characters (`openssl rand -hex 32`), for recovery and helpdesk tokens |
| `NOTIFY_EMAIL` | `true`, so users hear about every passkey change |

`ATTESTATION` doesn't need setting: with an allow-list, the class asks for `direct` attestation.

Don't use `UPGRADE` mode. Password managers create those passkeys, and the class refuses to load it with an allow-list.

## 5. Contracts

| Contract | Methods, in order | Purpose |
|---|---|---|
| **Enroll a YubiKey** | X.509 certificate, then a passkey method with `MODE=MANAGE` | Users add their YubiKey after proving their certificate. Also where they add a second key or remove a lost one |
| **YubiKey sign-in** | A passkey method with `MODE=LOGIN`, **Identifies User** on, and `PASSKEY_ONLY=true` | The new sign-in. `PASSKEY_ONLY` hides "Use another way to sign in" |
| **Certificate sign-in** | X.509 certificate, as today | Kept during the move, then retired |
| **Recovery** | X.509 certificate, then `MODE=RECOVERY` | For a user who has lost every YubiKey but still has a certificate |
| **Helpdesk** | YubiKey sign-in or X.509, then `MODE=HELPDESK` with `HELPDESK_GROUP_DN` | Agents issue recovery tokens; they must prove their own passkey too |

Putting the certificate before `MANAGE` is the strongest way to protect the first passkey: it's the "existing MFA method first" row in the README's [first-passkey](../../README.md#the-first-passkey) table. You don't need `ENROLL_GATES`. Never put Name/Password in front of the enrollment contract on its own.

The X.509 method must identify the user, as it does for certificate sign-in today, because `MANAGE` acts on the user the earlier method signed in.

## 6. Roll it out

1. Issue the keys, with their PINs set.
2. Have users sign in through **Enroll a YubiKey** and register their key. Encourage two keys per user, a daily one and a spare kept safe, so losing one isn't a helpdesk call.
3. Once a user has enrolled, they sign in through **YubiKey sign-in**.
4. When everyone has enrolled, retire **Certificate sign-in** and point applications and the default contract at **YubiKey sign-in**. While both contracts exist, a certificate still gets anyone in, so applications that should need a YubiKey must require that contract or its authentication level.
5. Keep the certificate in front of **Enroll a YubiKey** and **Recovery** for as long as you issue certificates. After that, use a [helpdesk token](../../README.md#helpdesk-tokens) or `ENROLL_GATES=helpdesk` instead.

## What to check

- Register a YubiKey you listed: it should save, and an email should arrive if `NOTIFY_EMAIL` is on.
- Try Touch ID, Windows Hello, a phone or a different YubiKey model: each should get "This kind of passkey isn't allowed here", with the reason in the log.
- Sign in through **YubiKey sign-in**: the browser should ask for the PIN and a touch.
- Passkeys registered before the allow-list was turned on keep working. Review users' manage pages, or clear the attribute, if they shouldn't.

## Limits

- Revocation lists aren't checked, because nodes may have no route to Yubico. To stop trusting a root, remove it from `ATTESTATION_TRUST_ROOTS`.
- The allow-list is checked when a passkey is created, not each time it's used. A key that's lost or stolen is dealt with by removing its passkey on the manage page, or through recovery.
- FIPS validation belongs to the YubiKey. The Identity Server side uses the Java runtime's normal cryptography, so if the customer needs FIPS-validated crypto on the server too, that's a separate question about NAM's own FIPS configuration.

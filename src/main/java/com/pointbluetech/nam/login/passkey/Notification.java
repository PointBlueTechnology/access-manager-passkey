package com.pointbluetech.nam.login.passkey;

/** The changes a user is emailed about. Each has notify.&lt;key&gt;.subject and .body in PasskeyMessages. */
enum Notification {
    PASSKEY_ADDED("added"),
    PASSKEY_REMOVED("removed"),
    CODES_REPLACED("codes"),
    RECOVERED_WITH_CODE("recoveredCode"),
    RECOVERED_WITH_TOKEN("recoveredToken"),
    HELPDESK_TOKEN_ISSUED("tokenIssued"),
    /** The one message that carries a code: the setup code the user asked for, before a first passkey. */
    ENROLL_CODE("enrollCode");

    final String key;

    Notification(String key) {
        this.key = key;
    }
}

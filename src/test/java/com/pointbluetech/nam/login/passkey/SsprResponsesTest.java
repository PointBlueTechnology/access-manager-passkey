package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.novell.ldapchai.cr.Challenge;
import com.novell.ldapchai.cr.ChaiChallenge;
import com.novell.ldapchai.cr.ChaiCrFactory;
import com.novell.ldapchai.provider.ChaiConfiguration;
import com.novell.ldapchai.provider.ChaiSetting;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/**
 * Checks answers stored by ldapchai, the library SSPR itself uses to write them (test scope only,
 * never shipped), so the formats here are SSPR's real ones rather than our reading of them.
 */
class SsprResponsesTest {

    private static final String PET = "What was your first pet's name?";
    private static final String CITY = "In what city were you born?";
    private static final String TEACHER = "Who was your favourite teacher?";
    private static final String STREET = "What street did you grow up on?";

    /** As SSPR writes it to the attribute: a 0002 record wrapping the XML. */
    private static String stored(String format, String iterations, boolean caseInsensitive) throws Exception {
        Map<Challenge, String> answers = new LinkedHashMap<>();
        answers.put(new ChaiChallenge(true, PET, 2, 255, true, 0, false), "Rex the Dog");
        answers.put(new ChaiChallenge(true, CITY, 2, 255, true, 0, false), "Ogden");
        answers.put(new ChaiChallenge(false, TEACHER, 2, 255, true, 0, false), "Mrs Ávila");
        answers.put(new ChaiChallenge(false, STREET, 2, 255, false, 0, false), "Elm Street");
        ChaiConfiguration config = ChaiConfiguration.builder()
                .setSetting(ChaiSetting.CR_DEFAULT_FORMAT_TYPE, format)
                .setSetting(ChaiSetting.CR_CASE_INSENSITIVE, String.valueOf(caseInsensitive))
                .setSetting(ChaiSetting.CR_CHAI_ITERATIONS, iterations)
                .build();
        return "0002#.#.#" + ChaiCrFactory.newChaiResponseSet(answers, Locale.ENGLISH, 1, config, "test-set").stringValue();
    }

    private static SsprResponses.Response question(SsprResponses set, String text) {
        return set.responses.stream().filter(r -> r.question.equals(text)).findFirst().orElseThrow();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "TEXT, 0",
            "MD5, 3",
            "SHA1, 3",
            "SHA1_SALT, 3",
            "SHA256_SALT, 3",
            "SHA512_SALT, 3",
            "PBKDF2, 1000",
            "PBKDF2_SHA256, 1000",
            "PBKDF2_SHA512, 1000",
            "BCRYPT, 4",
            "SCRYPT, 1024",
    })
    void checksEveryFormatSsprWrites(String format, String iterations) throws Exception {
        SsprResponses set = SsprResponses.parse(stored(format, iterations, true));
        assertEquals(4, set.responses.size());
        assertEquals(1, set.minRandomRequired);
        assertTrue(set.caseInsensitive);
        assertEquals(format, question(set, PET).format);

        assertTrue(set.matches(question(set, PET), "Rex the Dog"), format);
        assertTrue(set.matches(question(set, PET), "  rex THE dog "), format + " ignores case and edge spaces");
        assertTrue(set.matches(question(set, TEACHER), "mrs ávila"), format + " handles non-ASCII");
        assertFalse(set.matches(question(set, PET), "Rex"), format);
        assertFalse(set.matches(question(set, PET), "Ogden"), format + " answers aren't interchangeable");
        assertFalse(set.matches(question(set, PET), "   "), format);
        assertFalse(set.matches(question(set, PET), null), format);
    }

    @Test
    void caseSensitiveSetsKeepCase() throws Exception {
        SsprResponses set = SsprResponses.parse(stored("PBKDF2_SHA512", "1000", false));
        assertFalse(set.caseInsensitive);
        assertTrue(set.matches(question(set, CITY), "Ogden"));
        assertFalse(set.matches(question(set, CITY), "ogden"));
    }

    @Test
    void separatesRequiredAndRandomQuestions() throws Exception {
        SsprResponses set = SsprResponses.parse(stored("SHA1_SALT", "3", true));
        List<Integer> required = set.required();
        List<Integer> random = set.random();
        assertEquals(2, required.size());
        assertEquals(2, random.size());
        assertTrue(set.responses.get(required.get(0)).required);
        assertFalse(set.responses.get(random.get(0)).required);
    }

    @Test
    void findsTheRecordAmongOtherValuesAndFingerprintsIt() throws Exception {
        String record = stored("SHA256_SALT", "3", true);
        SsprResponses set = SsprResponses.from(List.of("v1:{\"id\":\"passkey\"}", record)).orElseThrow();
        assertEquals(SsprResponses.parse(record).fingerprint, set.fingerprint);
        assertFalse(SsprResponses.from(List.of("v1:{}", "rc1:abc")).isPresent());
    }

    @Test
    void refusesHostileOrBrokenXml() {
        String doctype = "0002#.#.#<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                + "<ResponseSet><response required=\"true\"><challenge>&x;</challenge><answer>a</answer></response></ResponseSet>";
        assertThrows(IllegalArgumentException.class, () -> SsprResponses.parse(doctype));
        assertThrows(IllegalArgumentException.class, () -> SsprResponses.parse("0002#.#.#<ResponseSet>"));
        assertThrows(IllegalArgumentException.class, () -> SsprResponses.parse("0001#.#.#<ResponseSet/>"));
    }

    @Test
    void helpdeskAndNmasAnswersNeverMatch() {
        String record = "0002#.#.#<ResponseSet minRandomRequired=\"0\" caseInsensitive=\"true\">"
                + "<response required=\"true\"><challenge>q</challenge><answer format=\"HELPDESK\">secret</answer></response>"
                + "<response required=\"true\"><challenge>r</challenge><answer format=\"NMAS\">secret</answer></response>"
                + "</ResponseSet>";
        SsprResponses set = SsprResponses.parse(record);
        assertFalse(set.matches(set.responses.get(0), "secret"));
        assertFalse(set.matches(set.responses.get(1), "secret"));
    }
}

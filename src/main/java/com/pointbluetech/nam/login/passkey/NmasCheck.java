package com.pointbluetech.nam.login.passkey;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One NMAS challenge-response login, waiting on its own thread for the user's answers. eDirectory
 * picks the questions part-way through the login, so the login has to stay open while the page
 * shows them, and the answers arrive on a later request. Checks are kept here by a random ID,
 * which the session holds, and are bounded in number and in how long they wait.
 */
final class NmasCheck {

    /** Runs the NMAS login on the check's thread; returns NMAS's status, 0 if every answer was right. */
    interface Login {
        int run(NmasCheck check) throws Exception;
    }

    /** NMAS's own codes for a login that was abandoned, and for a transport failure. */
    static final int CANCELLED = -1642;
    static final int TRANSPORT_FAILED = -1681;

    static final int MAX_CHECKS = 100;
    /** How long a finished check stays, so its result can still be collected. */
    private static final long KEEP_DONE_MS = 60_000;

    private static final Map<String, NmasCheck> CHECKS = new ConcurrentHashMap<>();
    private static final AtomicInteger THREADS = new AtomicInteger();
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum Phase { STARTING, ASKING, ANSWERED, DONE }

    final String id;
    private final String owner;
    private final long answerTimeoutNanos;
    private final long expiresAtNanos;

    private Phase phase = Phase.STARTING;
    private List<String> questions = Collections.emptyList();
    private List<String> answers;
    private int result;
    private String failure;
    private long doneAtNanos;

    private NmasCheck(String id, String owner, long answerTimeoutMs) {
        this.id = id;
        this.owner = owner;
        this.answerTimeoutNanos = TimeUnit.MILLISECONDS.toNanos(answerTimeoutMs);
        // Room to start, wait for answers and finish
        this.expiresAtNanos = System.nanoTime() + answerTimeoutNanos + TimeUnit.MINUTES.toNanos(2);
    }

    /**
     * Starts a login for the owner (the user's DN) on a new daemon thread. Empty if too many are
     * already waiting.
     */
    static Optional<NmasCheck> start(String owner, Login login, long answerTimeoutMs) {
        purge();
        if (CHECKS.size() >= MAX_CHECKS) {
            return Optional.empty();
        }
        byte[] random = new byte[18];
        RANDOM.nextBytes(random);
        NmasCheck check = new NmasCheck(Base64.getUrlEncoder().withoutPadding().encodeToString(random), owner,
                answerTimeoutMs);
        CHECKS.put(check.id, check);
        Thread thread = new Thread(() -> {
            int code;
            try {
                code = login.run(check);
            } catch (Exception | LinkageError e) {
                check.failed(e.toString());
                code = TRANSPORT_FAILED;
            }
            check.finish(code);
        }, "pbt-passkey-nmas-" + THREADS.incrementAndGet());
        thread.setDaemon(true);
        thread.start();
        return Optional.of(check);
    }

    /** The owner's check with this ID, if it's still there. */
    static Optional<NmasCheck> find(String id, String owner) {
        purge();
        NmasCheck check = id == null ? null : CHECKS.get(id);
        return check != null && check.owner.equals(owner) ? Optional.of(check) : Optional.empty();
    }

    /** Drops the check; one still waiting for answers is cancelled. */
    static void forget(String id) {
        NmasCheck check = id == null ? null : CHECKS.remove(id);
        if (check != null) {
            check.cancel();
        }
    }

    static int count() {
        return CHECKS.size();
    }

    private static void purge() {
        long now = System.nanoTime();
        CHECKS.values().removeIf(check -> check.expired(now));
    }

    private synchronized boolean expired(long now) {
        if (phase == Phase.DONE) {
            return now - doneAtNanos > TimeUnit.MILLISECONDS.toNanos(KEEP_DONE_MS);
        }
        if (now - expiresAtNanos > 0) {
            cancel();
            return true;
        }
        return false;
    }

    // --- The login thread's side

    /**
     * Shows the server's questions and waits for the answers. Empty if they don't come in time or
     * the check is cancelled, which ends the login.
     */
    synchronized Optional<List<String>> ask(List<String> asked) throws InterruptedException {
        if (phase != Phase.STARTING) {
            return Optional.empty();
        }
        questions = Collections.unmodifiableList(new ArrayList<>(asked));
        phase = Phase.ASKING;
        notifyAll();
        long deadline = System.nanoTime() + answerTimeoutNanos;
        while (phase == Phase.ASKING) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                phase = Phase.ANSWERED;
                return Optional.empty();
            }
            TimeUnit.NANOSECONDS.timedWait(this, left);
        }
        List<String> given = answers;
        // The login thread keeps its own reference only as long as the exchange needs it
        answers = null;
        return Optional.ofNullable(given);
    }

    private synchronized void failed(String reason) {
        failure = reason;
    }

    private synchronized void finish(int code) {
        result = code;
        answers = null;
        phase = Phase.DONE;
        doneAtNanos = System.nanoTime();
        notifyAll();
    }

    // --- The web requests' side

    /** The questions once the server has sent them; empty if the login ended first or it took too long. */
    synchronized Optional<List<String>> awaitQuestions(long timeoutMs) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (phase == Phase.STARTING) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                return Optional.empty();
            }
            TimeUnit.NANOSECONDS.timedWait(this, left);
        }
        return phase == Phase.ASKING ? Optional.of(questions) : Optional.empty();
    }

    /** The questions being asked, if the check is waiting for answers. */
    synchronized Optional<List<String>> waitingQuestions() {
        return phase == Phase.ASKING ? Optional.of(questions) : Optional.empty();
    }

    /** Hands the answers to the login; false if it isn't waiting for them any more. */
    synchronized boolean answer(List<String> given) {
        if (phase != Phase.ASKING) {
            return false;
        }
        answers = new ArrayList<>(given);
        phase = Phase.ANSWERED;
        notifyAll();
        return true;
    }

    /** NMAS's status once the login has ended. */
    synchronized OptionalInt awaitResult(long timeoutMs) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (phase != Phase.DONE) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                return OptionalInt.empty();
            }
            TimeUnit.NANOSECONDS.timedWait(this, left);
        }
        return OptionalInt.of(result);
    }

    synchronized boolean done() {
        return phase == Phase.DONE;
    }

    /** Why the login thread failed, if it did, for the log. */
    synchronized Optional<String> failure() {
        return Optional.ofNullable(failure);
    }

    private synchronized void cancel() {
        if (phase == Phase.STARTING || phase == Phase.ASKING) {
            phase = Phase.ANSWERED;
            answers = null;
            notifyAll();
        }
    }
}

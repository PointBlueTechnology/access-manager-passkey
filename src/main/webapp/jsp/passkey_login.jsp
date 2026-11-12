<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>
<%
    boolean pkIdentified = "identified".equals(request.getAttribute("pk_state"));
    boolean pkAllowId = Boolean.TRUE.equals(request.getAttribute("pk_allow_id"));
    boolean pkAllowUsernameless = Boolean.TRUE.equals(request.getAttribute("pk_allow_usernameless"));
    String pkOptions = (String) request.getAttribute("pk_options");
%>
<%-- No autocomplete="off" here: it can stop browsers offering passkeys in the ID field --%>
<form action="<%=pkFormUrl%>" method="post" id="pk_form">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_action" value="assert">
    <input type="hidden" name="pk_response" id="pk_response" value="">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page" style="margin: 25px; display: block">
    <% if (pkIdentified) { %>
        <div class="signin-div description" style="white-space: normal;">
            <%=pkHtml(PasskeyMessages.get(pkLocale, "login.signingInAs"))%> <strong><%=pkHtml(request.getAttribute("pk_userid"))%></strong>
        </div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <span id="pk_button" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "mfa.button"))%></span>
        </div>
        <div class="signin-div"><a href="#" id="pk_reset"><%=pkHtml(PasskeyMessages.get(pkLocale, "login.differentAccount"))%></a></div>
    <% } else { %>
        <% if (pkAllowId) { %>
        <div class="signin-div">
            <div class="input-signin-username">
                <input type="text" id="pk_userid" name="pk_userid" tabindex="1" autocomplete="username webauthn"
                       autocapitalize="none" spellcheck="false"
                       placeholder="<%=pkHtml(PasskeyMessages.get(pkLocale, "login.idPlaceholder"))%>">
            </div>
        </div>
        <% } %>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <% if (pkAllowId) { %>
            <span id="pk_continue" class="nam-signin-but action-but" role="button" tabindex="2"><%=pkHtml(PasskeyMessages.get(pkLocale, "login.continue"))%></span>
            <% } %>
            <% if (pkAllowUsernameless) { %>
            <span id="pk_button" class="nam-signin-but action-but" role="button" tabindex="3"><%=pkHtml(PasskeyMessages.get(pkLocale, "login.passkeyButton"))%></span>
            <% } %>
        </div>
    <% } %>
        <% if (pkRecoveryUrl != null && !pkRecoveryUrl.isEmpty()) { %>
        <div class="signin-div"><a href="<%=pkHtml(pkRecoveryUrl)%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "recovery.link"))%></a></div>
        <% } %>
    <% if (pkFallback != null && !pkFallback.isEmpty()) { %>
        <div class="signin-div"><a href="<%=pkHtml(pkFallback)%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "fallback.link"))%></a></div>
    <% } %>
    </div>
</form>
<% if (pkOptions != null) { %>
<script type="application/json" id="pk_options"><%=pkOptions%></script>
<% } %>
<script>
(function () {
    var form = document.getElementById("pk_form");
    var button = document.getElementById("pk_button");
    var attempt = 0;
    // Once a passkey's answer is on its way, nothing else may post: a second post arriving while the
    // first is still being checked finds no contract under way, and NAM answers with its default
    // password page even though the first signed the user in. A refusal brings a fresh copy of the page.
    var sent = false;

    function send(json) {
        if (sent) {
            return;
        }
        sent = true;
        PbtPasskey.abort();
        document.getElementById("pk_response").value = json;
        PbtPasskey.post(form);
    }

    /** Asks with a browser dialog. The message covers both cases, so it doesn't say whether a passkey exists. */
    function start(quiet) {
        // A click always starts over: a request can hang without the browser saying so, and this
        // also ends the autofill request. A browser allows one request at a time.
        if (sent) {
            return;
        }
        var thisAttempt = ++attempt;
        PbtPasskey.abort();
        PbtPasskey.showMessage("<%=pkJs(pkLocale, "mfa.working")%>");
        PbtPasskey.get().then(send).catch(function (error) {
            if (error.name === "AbortError" || thisAttempt !== attempt) {
                return; // a newer copy of this page took over
            }
            console.warn("Passkey request ended:", error.name, error.message);
            if (error.name === "NotAllowedError") {
                PbtPasskey.showMessage(quiet ? "" : "<%=pkJs(pkLocale, "login.noneOrCancelled")%>");
            } else {
                PbtPasskey.showMessage(PbtPasskey.errorMessage(error));
            }
        });
    }

    if (button) {
        PbtPasskey.onActivate(button, function () { start(false); });
    }

    <% if (pkIdentified) { %>
    document.getElementById("pk_reset").addEventListener("click", function (event) {
        event.preventDefault();
        document.getElementById("pk_action").value = "reset";
        PbtPasskey.post(form);
    });
    if (!PbtPasskey.isSupported()) {
        button.style.display = "none";
        PbtPasskey.showMessage(PbtPasskey.browserMessage);
        return;
    }
    <%     if (pkMessage == null) { %>
    start(true);
    <%     } %>
    <% } else { %>
    var field = document.getElementById("pk_userid");

    function identify() {
        if (sent) {
            return;
        }
        if (!field.value.trim()) {
            PbtPasskey.showMessage("<%=pkJs(pkLocale, "login.idRequired")%>");
            field.focus();
            return;
        }
        document.getElementById("pk_action").value = "identify";
        // End the autofill request first: if it's still open when the next page asks for a passkey,
        // Safari can leave that request hanging with no prompt
        PbtPasskey.abort().then(function () {
            PbtPasskey.post(form);
        });
    }

    if (field) {
        PbtPasskey.onActivate(document.getElementById("pk_continue"), identify);
        field.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
                identify();
            }
        });
    }
    if (!PbtPasskey.isSupported()) {
        if (button) {
            button.style.display = "none";
        }
        PbtPasskey.showMessage(PbtPasskey.browserMessage);
        return;
    }
    <%     if (pkAllowUsernameless && pkAllowId) { %>
    // Passkeys appear in the browser's autofill for the ID field; this waits until one is picked.
    // The field isn't focused automatically: some browsers only offer them when focus arrives after
    // this request has started.
    PbtPasskey.isAutofillAvailable().then(function (available) {
        if (!available) {
            console.info("Passkey autofill is not available in this browser");
            return;
        }
        return PbtPasskey.get("conditional").then(send);
    }).catch(function (error) {
        // The field and the button still work; the console says why autofill didn't
        if (error.name !== "AbortError") {
            console.warn("Passkey autofill request ended:", error.name, error.message);
        }
    });
    <%     } %>
    <% } %>
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

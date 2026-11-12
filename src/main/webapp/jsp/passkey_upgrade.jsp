<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>
<%--
    UPGRADE mode: shown for a moment after the password. Asks the browser to create a passkey by
    itself (conditional create), which it does only if its password manager just filled in this
    user's password. Whatever happens, the form is posted and the sign-in carries on.
--%>
<%
    String pkCsrfField = pkCsrfRequired
            ? "<input type=\"hidden\" name=\"AntiCSRFToken\" value=\"" + pkHtml(pkSessionData.getAntiCSRFToken()) + "\">"
            : "";
%>
<form action="<%=pkFormUrl%>" method="post" id="pk_upgrade_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_upgrade_action" value="skip">
    <input type="hidden" name="pk_response" id="pk_upgrade_response" value="">
    <input type="hidden" name="pk_reason" id="pk_upgrade_reason" value="">
    <%=pkCsrfField%>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div description" style="white-space: normal;"><%=pkHtml(PasskeyMessages.get(pkLocale, "upgrade.working"))%></div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; display: none"></div>
        <div class="closure-but signin-div">
            <span id="pk_upgrade_continue" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.continue"))%></span>
        </div>
    </div>
</form>
<script type="application/json" id="pk_options"><%=request.getAttribute("pk_options")%></script>
<script>
(function () {
    // Browsers answer at once when they won't create one; this only covers one that never answers
    var WAIT_MS = 8000;
    var form = document.getElementById("pk_upgrade_form");
    var finished = false;
    var timedOut = false;

    function finish(action, reason, response) {
        if (finished) {
            return;
        }
        finished = true;
        document.getElementById("pk_upgrade_action").value = action;
        document.getElementById("pk_upgrade_reason").value = reason || "";
        document.getElementById("pk_upgrade_response").value = response || "";
        PbtPasskey.post(form);
    }

    PbtPasskey.onActivate(document.getElementById("pk_upgrade_continue"), function () {
        PbtPasskey.abort();
        finish("skip", "continued");
    });

    PbtPasskey.isConditionalCreateAvailable().then(function (available) {
        if (!available) {
            finish("skip", "unsupported");
            return;
        }
        var timer = setTimeout(function () {
            timedOut = true;
            PbtPasskey.abort();
            finish("skip", "timeout");
        }, WAIT_MS);
        PbtPasskey.create("conditional").then(function (json) {
            clearTimeout(timer);
            finish("register", "", json);
        }).catch(function (error) {
            clearTimeout(timer);
            if (error && error.name === "AbortError" && !timedOut) {
                return; // a newer copy of this page took over, or Continue was pressed
            }
            finish("skip", error && error.name ? error.name : "failed");
        });
    });
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

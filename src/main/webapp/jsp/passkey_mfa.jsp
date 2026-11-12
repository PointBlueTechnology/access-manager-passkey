<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>

<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" value="assert">
    <input type="hidden" name="pk_response" id="pk_response" value="">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div description" style="white-space: normal;"><%=pkHtml(request.getAttribute("pk_intro") != null ? request.getAttribute("pk_intro") : PasskeyMessages.get(pkLocale, "mfa.intro"))%></div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <span id="pk_button" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "mfa.button"))%></span>
        </div>
        <% if (pkRecoveryUrl != null && !pkRecoveryUrl.isEmpty()) { %>
        <div class="signin-div"><a href="<%=pkHtml(pkRecoveryUrl)%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "recovery.link"))%></a></div>
        <% } %>
        <% if (pkFallback != null && !pkFallback.isEmpty()) { %>
        <div class="signin-div"><a href="<%=pkHtml(pkFallback)%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "fallback.link"))%></a></div>
        <% } %>
    </div>
</form>
<script type="application/json" id="pk_options"><%=request.getAttribute("pk_options")%></script>
<script>
(function () {
    var button = document.getElementById("pk_button");
    var working = false;

    function start(quiet) {
        if (working) {
            return;
        }
        working = true;
        PbtPasskey.showMessage("<%=pkJs(pkLocale, "mfa.working")%>");
        PbtPasskey.get().then(function (json) {
            document.getElementById("pk_response").value = json;
            PbtPasskey.post(document.getElementById("pk_form"));
        }).catch(function (error) {
            working = false;
            if (error.name === "AbortError") {
                return; // a newer copy of this page took over
            }
            // Some browsers refuse to prompt until the user clicks; the button is still there
            PbtPasskey.showMessage(quiet && error.name === "NotAllowedError" ? "" : PbtPasskey.errorMessage(error));
        });
    }

    if (!PbtPasskey.isSupported()) {
        button.style.display = "none";
        PbtPasskey.showMessage(PbtPasskey.browserMessage);
        return;
    }
    PbtPasskey.onActivate(button, function () { start(false); });
    <% if (pkMessage == null) { %>
    start(true);
    <% } %>
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

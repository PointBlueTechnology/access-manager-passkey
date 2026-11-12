<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" value="recover">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div description" style="white-space: normal; max-width: 480px;"><%=pkHtml(PasskeyMessages.get(pkLocale, "recovery.intro"))%></div>
        <div class="signin-div">
            <div class="input-signin-code">
                <input type="text" id="pk_code" name="pk_code" autocomplete="off" autocapitalize="characters" spellcheck="false"
                       placeholder="<%=pkHtml(PasskeyMessages.get(pkLocale, "recovery.placeholder"))%>">
            </div>
        </div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <span id="pk_button" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "login.continue"))%></span>
        </div>
    </div>
</form>
<script>
(function () {
    var field = document.getElementById("pk_code");

    function submit() {
        if (!field.value.trim()) {
            PbtPasskey.showMessage("<%=pkJs(pkLocale, "recovery.required")%>");
            field.focus();
            return;
        }
        PbtPasskey.post(document.getElementById("pk_form"));
    }

    PbtPasskey.onActivate(document.getElementById("pk_button"), submit);
    field.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            submit();
        }
    });
    field.focus();
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

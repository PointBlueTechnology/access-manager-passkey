<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>
<%
    String pkIssued = (String) request.getAttribute("pk_issued_token");
%>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_action" value="issue">
    <input type="hidden" name="pk_token" value="<%=pkHtml(request.getAttribute("pk_token"))%>">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div" style="font-size: 16px; font-weight: bold;"><%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.title"))%></div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; max-width: 520px; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
    <% if (pkIssued != null) { %>
        <div class="signin-div description" style="white-space: normal; max-width: 520px;">
            <%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.issuedFor"))%> <strong><%=pkHtml(request.getAttribute("pk_issued_user"))%></strong>.
            <%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.expires"))%> <%=pkHtml(request.getAttribute("pk_issued_expires"))%>.
            <%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.showOnce"))%>
        </div>
        <div class="signin-div" style="font-family: monospace; font-size: 18px;"><%=pkHtml(pkIssued)%></div>
    <% } else { %>
        <div class="signin-div description" style="white-space: normal; max-width: 520px;"><%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.intro"))%></div>
        <div class="signin-div">
            <div class="input-signin-username">
                <input type="text" id="pk_target" name="pk_target" autocomplete="off" autocapitalize="none" spellcheck="false"
                       placeholder="<%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.targetPlaceholder"))%>">
            </div>
        </div>
        <% for (int pkItem = 1; pkItem <= 3; pkItem++) { %>
        <div class="signin-div" style="white-space: normal; max-width: 520px;">
            <label><input type="checkbox" name="pk_check<%=pkItem%>" value="on"> <%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.check" + pkItem))%></label>
        </div>
        <% } %>
    <% } %>
        <div class="closure-but signin-div">
            <% if (pkIssued == null) { %>
            <span id="pk_issue" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.issue"))%></span>
            <% } else { %>
            <span id="pk_another" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "helpdesk.another"))%></span>
            <% } %>
            <span id="pk_done" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.done"))%></span>
        </div>
    </div>
</form>
<script>
(function () {
    var form = document.getElementById("pk_form");

    function send(action) {
        document.getElementById("pk_action").value = action;
        PbtPasskey.post(form);
    }

    var issue = document.getElementById("pk_issue");
    if (issue) {
        PbtPasskey.onActivate(issue, function () { send("issue"); });
    }
    var another = document.getElementById("pk_another");
    if (another) {
        PbtPasskey.onActivate(another, function () { send("list"); });
    }
    PbtPasskey.onActivate(document.getElementById("pk_done"), function () { send("done"); });
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

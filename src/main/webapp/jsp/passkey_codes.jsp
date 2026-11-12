<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ page import="java.util.List" %>
<%@ include file="passkey_common.jspf" %>
<%
    @SuppressWarnings("unchecked")
    List<String> pkCodes = (List<String>) request.getAttribute("pk_codes");
%>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" value="list">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div" style="font-size: 16px; font-weight: bold;"><%=pkHtml(PasskeyMessages.get(pkLocale, "codes.title"))%></div>
        <div class="signin-div description" style="white-space: normal; max-width: 520px;"><%=pkHtml(PasskeyMessages.get(pkLocale, "codes.intro"))%></div>
        <div class="signin-div" id="pk_code_list" style="font-family: monospace; font-size: 15px; line-height: 1.7;">
            <% for (String pkCode : pkCodes) { %>
            <div><%=pkHtml(pkCode)%></div>
            <% } %>
        </div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; display: none"></div>
        <div class="closure-but signin-div">
            <span id="pk_copy" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "codes.copy"))%></span>
            <span id="pk_done" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "codes.saved"))%></span>
        </div>
    </div>
</form>
<script>
(function () {
    PbtPasskey.onActivate(document.getElementById("pk_copy"), function () {
        var rows = document.querySelectorAll("#pk_code_list div");
        var text = Array.prototype.map.call(rows, function (row) { return row.textContent; }).join("\n");
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function () {
                PbtPasskey.showMessage("<%=pkJs(pkLocale, "codes.copied")%>");
            });
        }
    });
    PbtPasskey.onActivate(document.getElementById("pk_done"), function () {
        PbtPasskey.post(document.getElementById("pk_form"));
    });
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

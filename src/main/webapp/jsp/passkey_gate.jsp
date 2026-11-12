<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>
<%@ page import="java.util.List" %>
<%
    boolean pkEmailGate = "email".equals(request.getAttribute("pk_gate"));
    @SuppressWarnings("unchecked")
    List<String> pkQuestions = (List<String>) request.getAttribute("pk_questions");
    boolean pkCanResend = Boolean.TRUE.equals(request.getAttribute("pk_can_resend"));
    String pkIntro = pkQuestions != null ? PasskeyMessages.get(pkLocale, "gate.questionsIntro")
            : pkEmailGate
            ? PasskeyMessages.get(pkLocale, "gate.emailIntro").replace("{address}", String.valueOf(request.getAttribute("pk_gate_address")))
            : PasskeyMessages.get(pkLocale, "gate.helpdeskIntro");
%>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_action" value="gate">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div description" style="white-space: normal; max-width: 480px;"><%=pkHtml(pkIntro)%></div>
        <% if (pkQuestions != null) { %>
        <% for (int pkI = 0; pkI < pkQuestions.size(); pkI++) { %>
        <div class="signin-div" style="white-space: normal; max-width: 480px;">
            <label for="pk_answer<%=pkI%>"><%=pkHtml(pkQuestions.get(pkI))%></label>
            <div class="input-signin-code">
                <input type="password" id="pk_answer<%=pkI%>" name="pk_answer<%=pkI%>" class="pk-gate-field"
                       autocomplete="off" spellcheck="false"
                       placeholder="<%=pkHtml(PasskeyMessages.get(pkLocale, "gate.answerPlaceholder"))%>">
            </div>
        </div>
        <% } %>
        <% } else { %>
        <div class="signin-div">
            <div class="input-signin-code">
                <input type="text" id="pk_gate_code" name="pk_code" spellcheck="false" class="pk-gate-field"
                       autocomplete="<%=pkEmailGate ? "one-time-code" : "off"%>"
                       <%=pkEmailGate ? "inputmode=\"numeric\"" : "autocapitalize=\"characters\""%>
                       placeholder="<%=pkHtml(PasskeyMessages.get(pkLocale, pkEmailGate ? "gate.emailPlaceholder" : "gate.helpdeskPlaceholder"))%>">
            </div>
        </div>
        <% } %>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <span id="pk_button" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "login.continue"))%></span>
        </div>
        <% if (pkEmailGate && pkCanResend) { %>
        <div class="signin-div"><a href="#" id="pk_resend"><%=pkHtml(PasskeyMessages.get(pkLocale, "gate.resend"))%></a></div>
        <% } %>
    </div>
</form>
<script>
(function () {
    var form = document.getElementById("pk_form");
    var fields = Array.prototype.slice.call(document.querySelectorAll(".pk-gate-field"));
    var field = fields[0];

    function submit() {
        var empty = fields.filter(function (f) { return !f.value.trim(); })[0];
        if (empty) {
            PbtPasskey.showMessage("<%=pkJs(pkLocale, "recovery.required")%>");
            empty.focus();
            return;
        }
        PbtPasskey.post(form);
    }

    PbtPasskey.onActivate(document.getElementById("pk_button"), submit);
    fields.forEach(function (f) {
        f.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
                submit();
            }
        });
    });
    var resend = document.getElementById("pk_resend");
    if (resend) {
        resend.addEventListener("click", function (event) {
            event.preventDefault();
            document.getElementById("pk_action").value = "gate_send";
            fields.forEach(function (f) { f.value = ""; });
            PbtPasskey.post(form);
        });
    }
    field.focus();
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

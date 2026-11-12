<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ include file="passkey_common.jspf" %>
<%
    boolean pkSaved = "saved".equals(request.getAttribute("pk_state"));
    String pkSavedName = (String) request.getAttribute("pk_saved_name");
    String pkCsrfField = pkCsrfRequired
            ? "<input type=\"hidden\" name=\"AntiCSRFToken\" value=\"" + pkHtml(pkSessionData.getAntiCSRFToken()) + "\">"
            : "";
%>

<% if (pkSaved) { %>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_action" value="done">
    <%=pkCsrfField%>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div description" style="white-space: normal;">
            <% if (pkSavedName != null) { %>
            <%=pkHtml(PasskeyMessages.get(pkLocale, "register.saved"))%> <strong><%=pkHtml(pkSavedName)%></strong>
            <% } else { %>
            <%=pkHtml(PasskeyMessages.get(pkLocale, "register.savedNoName"))%>
            <% } %>
        </div>
        <div class="signin-div description" style="white-space: normal;"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.addHint"))%></div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <span id="pk_add" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.addAnother"))%></span>
            <span id="pk_continue" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.continue"))%></span>
        </div>
    </div>
</form>
<script>
(function () {
    function send(action) {
        document.getElementById("pk_action").value = action;
        PbtPasskey.post(document.getElementById("pk_form"));
    }
    PbtPasskey.onActivate(document.getElementById("pk_continue"), function () { send("done"); });
    PbtPasskey.onActivate(document.getElementById("pk_add"), function () { send("add"); });
})();
</script>

<% } else { %>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_action" value="register">
    <input type="hidden" name="pk_response" id="pk_response" value="">
    <%=pkCsrfField%>

    <div class="content login-page" style="margin: 25px; display: block">
        <div class="signin-div description" style="white-space: normal;"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.intro"))%></div>
        <div class="signin-div">
            <label for="pk_name"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.nameLabel"))%></label>
            <div class="input-signin-code">
                <input type="text" id="pk_name" name="pk_name" maxlength="<%=pkHtml(request.getAttribute("pk_max_name"))%>"
                       placeholder="<%=pkHtml(PasskeyMessages.get(pkLocale, "register.namePlaceholder"))%>">
            </div>
        </div>
        <div id="pk_msg" class="signin-div" role="alert" style="white-space: normal; <%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <div class="closure-but signin-div">
            <span id="pk_button" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "register.button"))%></span>
        </div>
        <% if (request.getAttribute("pk_cancel") != null) { %>
        <div class="signin-div"><a href="#" id="pk_cancel"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.cancel"))%></a></div>
        <% } else if (pkFallback != null && !pkFallback.isEmpty()) { %>
        <div class="signin-div"><a href="<%=pkHtml(pkFallback)%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "fallback.link"))%></a></div>
        <% } %>
    </div>
</form>
<script type="application/json" id="pk_options"><%=request.getAttribute("pk_options")%></script>
<script>
(function () {
    var button = document.getElementById("pk_button");
    var working = false;

    function start() {
        if (working) {
            return;
        }
        working = true;
        PbtPasskey.showMessage("<%=pkJs(pkLocale, "register.working")%>");
        PbtPasskey.create().then(function (json) {
            document.getElementById("pk_response").value = json;
            PbtPasskey.post(document.getElementById("pk_form"));
        }).catch(function (error) {
            working = false;
            if (error.name === "AbortError") {
                return; // a newer copy of this page took over
            }
            PbtPasskey.showMessage(PbtPasskey.errorMessage(error));
        });
    }

    var cancel = document.getElementById("pk_cancel");
    if (cancel) {
        cancel.addEventListener("click", function (event) {
            event.preventDefault();
            document.getElementById("pk_action").value = "list";
            PbtPasskey.post(document.getElementById("pk_form"));
        });
    }
    if (!PbtPasskey.isSupported()) {
        button.style.display = "none";
        PbtPasskey.showMessage(PbtPasskey.browserMessage);
        return;
    }
    PbtPasskey.onActivate(button, start);
    document.getElementById("pk_name").addEventListener("keydown", function (event) {
        // Enter would submit the form with no credential
        if (event.key === "Enter") {
            event.preventDefault();
            start();
        }
    });
})();
</script>
<% } %>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

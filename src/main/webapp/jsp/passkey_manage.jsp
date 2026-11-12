<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8" %>
<%@ page import="java.util.List" %>
<%@ page import="com.pointbluetech.nam.login.passkey.PasskeyView" %>
<%@ include file="passkey_common.jspf" %>
<%
    @SuppressWarnings("unchecked")
    List<PasskeyView> pkRows = (List<PasskeyView>) request.getAttribute("pk_rows");
    boolean pkCanAdd = Boolean.TRUE.equals(request.getAttribute("pk_can_add"));
    boolean pkCanRemove = Boolean.TRUE.equals(request.getAttribute("pk_can_remove"));
    boolean pkSingleWarning = Boolean.TRUE.equals(request.getAttribute("pk_single_warning"));
    Object pkCodesLeft = request.getAttribute("pk_codes_left");
    Object pkCodesAfter = request.getAttribute("pk_codes_after");
    boolean pkReview = Boolean.TRUE.equals(request.getAttribute("pk_review"));
%>
<style>
    .pk-manage-title { font-size: 16px; font-weight: bold; }
    .pk-manage-note { white-space: normal; max-width: 640px; }
    .pk-manage-table-wrap { margin: 15px 0 0 45px; overflow-x: auto; }
    .pk-manage-table { border-collapse: collapse; }
    .pk-manage-table th { padding: 8px 24px 8px 0; text-align: left; font-weight: bold; border-bottom: 1px solid #dae1e1; }
    .pk-manage-table td { padding: 10px 24px 10px 0; border-bottom: 1px solid #dae1e1; white-space: nowrap; }
    .pk-manage-table .pk-manage-actions { padding-right: 0; }
    .pk-manage-actions a + a { margin-left: 12px; }
    .pk-manage-detail { display: block; font-size: 12px; color: #697374; }
    @media (max-width: 600px) {
        .pk-manage .signin-div, .pk-manage-table-wrap { margin-left: 0; }
        .pk-manage-table .pk-manage-date { display: none; }
        .pk-manage-table td { white-space: normal; }
        .pk-manage-table .pk-manage-actions { white-space: nowrap; }
    }
</style>
<form action="<%=pkFormUrl%>" method="post" id="pk_form" autocomplete="off">
    <input type="hidden" name="option" value="credential">
    <input type="hidden" name="pk_action" id="pk_action" value="">
    <input type="hidden" name="pk_cred_id" id="pk_cred_id" value="">
    <input type="hidden" name="pk_name" id="pk_name" value="">
    <input type="hidden" name="pk_token" value="<%=pkHtml(request.getAttribute("pk_token"))%>">
    <% if (pkCsrfRequired) { %>
    <input type="hidden" name="AntiCSRFToken" value="<%=pkHtml(pkSessionData.getAntiCSRFToken())%>">
    <% } %>

    <div class="content login-page pk-manage" style="margin: 25px; display: block">
        <div class="signin-div pk-manage-title"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.title"))%></div>
        <div id="pk_msg" class="signin-div pk-manage-note" role="alert" style="<%=pkMessage == null ? "display: none" : ""%>"><%=pkHtml(pkMessage)%></div>
        <% if (pkReview) { %>
        <div id="pk_review" class="signin-div pk-manage-note"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.review"))%></div>
        <% } %>
        <% if (pkSingleWarning) { %>
        <div class="signin-div pk-manage-note"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.singleWarning"))%></div>
        <% } %>

        <% if (pkRows.isEmpty()) { %>
        <div class="signin-div pk-manage-note"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.empty"))%></div>
        <% } else { %>
        <div class="pk-manage-table-wrap">
        <table class="pk-manage-table">
            <thead>
                <tr>
                    <th scope="col"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.colName"))%></th>
                    <th scope="col" class="pk-manage-date"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.colCreated"))%></th>
                    <th scope="col" class="pk-manage-date"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.colLastUsed"))%></th>
                    <th scope="col"></th>
                </tr>
            </thead>
            <tbody>
            <% for (PasskeyView pkRow : pkRows) { %>
                <tr>
                    <td>
                        <%=pkHtml(pkRow.name())%>
                        <span class="pk-manage-detail"><%=pkHtml(pkRow.provider())%><%=pkRow.provider().isEmpty() ? "" : " &middot; "%><%=pkHtml(PasskeyMessages.get(pkLocale, pkRow.synced() ? "manage.synced" : "manage.deviceOnly"))%><% if (pkRow.viaRecovery()) { %> &middot; <%=pkHtml(PasskeyMessages.get(pkLocale, "manage.viaRecovery"))%><% } %></span>
                    </td>
                    <td class="pk-manage-date"><%=pkHtml(pkRow.created())%></td>
                    <td class="pk-manage-date"><%=pkHtml(pkRow.lastUsed().isEmpty() ? PasskeyMessages.get(pkLocale, "manage.never") : pkRow.lastUsed())%></td>
                    <td class="pk-manage-actions">
                        <a href="#" class="pk-rename" data-id="<%=pkHtml(pkRow.id())%>" data-name="<%=pkHtml(pkRow.name())%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.rename"))%></a>
                        <% if (pkCanRemove) { %>
                        <a href="#" class="pk-remove" data-id="<%=pkHtml(pkRow.id())%>" data-name="<%=pkHtml(pkRow.name())%>"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.remove"))%></a>
                        <% } %>
                    </td>
                </tr>
            <% } %>
            </tbody>
        </table>
        </div>
        <% } %>

        <% if (pkCodesLeft != null) { %>
        <div class="signin-div pk-manage-note">
            <%=pkHtml(PasskeyMessages.get(pkLocale, "codes.manageLeft"))%> <%=pkHtml(pkCodesLeft)%>.
            <% if (pkCodesAfter == null) { %>
            <a href="#" id="pk_codes"><%=pkHtml(PasskeyMessages.get(pkLocale, "codes.generate"))%></a>
            <% } else { %>
            <span id="pk_codes_wait"><%=pkHtml(PasskeyMessages.get(pkLocale, "codes.after").replace("{time}", String.valueOf(pkCodesAfter)))%></span>
            <% } %>
        </div>
        <% } %>

        <div class="closure-but signin-div">
            <% if (pkCanAdd) { %>
            <span id="pk_add" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.add"))%></span>
            <% } %>
            <span id="pk_done" class="nam-signin-but action-but" role="button" tabindex="0"><%=pkHtml(PasskeyMessages.get(pkLocale, "manage.done"))%></span>
        </div>
    </div>
</form>
<script>
(function () {
    function send(action, id, name) {
        document.getElementById("pk_action").value = action;
        document.getElementById("pk_cred_id").value = id || "";
        document.getElementById("pk_name").value = name || "";
        PbtPasskey.post(document.getElementById("pk_form"));
    }

    function eachLink(selector, handler) {
        Array.prototype.forEach.call(document.querySelectorAll(selector), function (link) {
            link.addEventListener("click", function (event) {
                event.preventDefault();
                handler(link);
            });
        });
    }

    eachLink(".pk-rename", function (link) {
        var name = window.prompt("<%=pkJs(pkLocale, "manage.renamePrompt")%>", link.getAttribute("data-name"));
        if (name !== null) {
            send("rename", link.getAttribute("data-id"), name);
        }
    });
    eachLink(".pk-remove", function (link) {
        if (window.confirm("<%=pkJs(pkLocale, "manage.removeConfirm")%> " + link.getAttribute("data-name"))) {
            send("delete", link.getAttribute("data-id"));
        }
    });
    eachLink("#pk_codes", function () {
        if (window.confirm("<%=pkJs(pkLocale, "codes.generateConfirm")%>")) {
            send("codes");
        }
    });
    var add = document.getElementById("pk_add");
    if (add) {
        PbtPasskey.onActivate(add, function () { send("add"); });
    }
    PbtPasskey.onActivate(document.getElementById("pk_done"), function () { send("done"); });
})();
</script>
<% if (pkStandalone) { %>
</body>
</html>
<% } %>

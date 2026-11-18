/* 메일 가드 — 새 Outlook 추가 기능 화면 */
(function () {
  "use strict";

  var NOTICE_KEY = "mailguard";
  var MAX_ATTACH_BYTES = 10 * 1024 * 1024;
  var runId = 0;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function getBody(item, type) {
    return new Promise(function (resolve) {
      item.body.getAsync(type, function (r) { resolve(r.status === Office.AsyncResultStatus.Succeeded ? r.value : ""); });
    });
  }

  function base64ToBytes(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function getAttachmentBytes(item, att) {
    return new Promise(function (resolve) {
      if (!item.getAttachmentContentAsync) return resolve(null);
      item.getAttachmentContentAsync(att.id, function (r) {
        if (r.status !== Office.AsyncResultStatus.Succeeded) return resolve(null);
        if (r.value.format !== Office.MailboxEnums.AttachmentContentFormat.Base64) return resolve(null);
        try { resolve(base64ToBytes(r.value.content)); } catch (e) { resolve(null); }
      });
    });
  }

  function scanAttachments(item) {
    var atts = (item.attachments || []).filter(function (a) {
      var ext = (/\.[^.]+$/.exec((a.name || "").toLowerCase()) || [""])[0];
      return !a.isInline && a.size && a.size <= MAX_ATTACH_BYTES && MailGuardRules.ATTACH_EXTS.indexOf(ext) >= 0;
    });
    return Promise.all(atts.map(function (a) {
      return getAttachmentBytes(item, a).then(function (bytes) {
        if (!bytes) return { name: a.name, links: [] };
        return MailGuardRules.linksInAttachment(a.name, bytes).then(function (links) {
          return { name: a.name, links: links };
        });
      });
    }));
  }

  function setNotice(item, level, reasons) {
    var nm = item.notificationMessages;
    if (!nm) return;
    if (level === "정상") { nm.removeAsync(NOTICE_KEY); return; }
    var head = level === "위험"
      ? "⛔ 악성 의심 메일: 열지 말고 링크·첨부파일을 누르지 마세요. PI팀에 신고하세요."
      : "⚠ 외부 메일에 링크가 있습니다. 보낸 사람을 확인하기 전에는 클릭하지 마세요.";
    var msg = (head + " " + (reasons[0] || "").replace(/^\[규칙\d\]\s*/, "")).slice(0, 150);
    nm.replaceAsync(NOTICE_KEY, { type: Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage, message: msg });
  }

  function render(state, item, reasons) {
    var box = document.getElementById("result"), det = document.getElementById("details");
    var map = {
      "위험": ["danger", "위험 · 열지 말 것", "유명 회사나 우리 회사를 흉내 낸 가짜 주소입니다. 링크와 첨부파일을 절대 누르지 말고 PI팀에 신고하세요."],
      "주의": ["warn", "주의 · 확인 필요", "외부에서 온 메일에 링크가 있습니다. 보낸 사람이 아는 거래처인지 확인하기 전에는 링크와 첨부파일을 누르지 마세요."],
      "정상": ["ok", "규칙에 걸리지 않음", "두 규칙(유명 도메인 사칭, 외부 메일 링크)에 해당하지 않습니다. 그래도 이상하면 신고하세요."],
      "없음": ["wait", "메일을 선택하세요", "메일을 선택하면 자동으로 검사합니다."],
      "오류": ["wait", "검사하지 못했습니다", "메일을 다시 선택해 보세요."],
    };
    var m = map[state];
    box.className = "card " + m[0];
    box.innerHTML = "<h1>" + esc(m[1]) + "</h1><p>" + esc(m[2]) + "</p>";
    if (!item || state === "없음" || state === "오류") { det.innerHTML = ""; return; }
    var from = item.from || {};
    var html = "<h2>보낸 사람</h2><div class='meta'>" + esc(from.displayName) + " &lt;" + esc(from.emailAddress) + "&gt;</div>";
    if (reasons && reasons.length) {
      html += "<h2>이유</h2><ul>" + reasons.map(function (r) { return "<li>" + esc(r) + "</li>"; }).join("") + "</ul>";
    }
    det.innerHTML = html;
  }

  function run() {
    var item = Office.context.mailbox.item, myRun = ++runId;
    if (!item || item.itemType !== Office.MailboxEnums.ItemType.Message) { render("없음"); return; }
    render("없음");
    document.getElementById("result").innerHTML = "<h1>검사 중…</h1><p>메일을 확인하고 있습니다.</p>";

    var ctx = MailGuardRules.makeContext(MAILGUARD_CONFIG, Office.context.mailbox.userProfile.emailAddress);
    var from = item.from || {};
    var external = MailGuardRules.isExternal(MailGuardRules.domainOf(from.emailAddress), ctx);

    Promise.all([
      getBody(item, Office.CoercionType.Html),
      getBody(item, Office.CoercionType.Text),
      external && MAILGUARD_CONFIG.scanAttachmentLinks ? scanAttachments(item) : Promise.resolve([]),
    ]).then(function (v) {
      if (myRun !== runId) return; // 그 사이 다른 메일을 선택함
      var res = MailGuardRules.analyze({
        fromAddress: from.emailAddress, fromName: from.displayName,
        html: v[0], text: v[1], attachmentLinks: v[2],
      }, ctx);
      render(res.level, item, res.reasons);
      setNotice(item, res.level, res.reasons);
    }).catch(function () {
      if (myRun === runId) render("오류");
    });
  }

  Office.onReady(function () {
    // 창을 고정(압정)해 두면 메일을 바꿔 선택할 때마다 다시 검사
    if (Office.context.mailbox.addHandlerAsync) {
      Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, run);
    }
    run();
  });
})();

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
    // 메일 제목 아래 줄에 세 단계 모두 표시. 줄 색은 Outlook이 정하므로 색 동그라미로 구분
    var T = Office.MailboxEnums.ItemNotificationMessageType;
    var reason = (reasons[0] || "").replace(/^\[규칙\d\]\s*/, "");
    var notice;
    if (level === "위험") {
      notice = { type: T.ErrorMessage,
        message: "🔴 [위험] 악성 의심 메일입니다. 링크·첨부파일을 누르지 말고 PI팀에 신고하세요. " + reason };
    } else if (level === "주의") {
      notice = { type: T.InformationalMessage, icon: "Icon16", persistent: false,
        message: "🟡 [주의] 외부 메일에 링크가 있습니다. 보낸 사람을 확인하기 전에는 누르지 마세요. " + reason };
    } else {
      notice = { type: T.InformationalMessage, icon: "Icon16", persistent: false,
        message: "🟢 [정상] 메일 가드 규칙(사칭 주소·외부 링크)에 해당하지 않습니다." };
    }
    notice.message = notice.message.slice(0, 150);
    nm.replaceAsync(NOTICE_KEY, notice, function (r) {
      // 아이콘 문제 등으로 실패하면 아이콘 없는 형식으로 다시 시도
      // (정상은 빨간 오류 모양으로 띄우면 오해를 부르므로 주의만 다시 시도)
      if (r && r.status !== Office.AsyncResultStatus.Succeeded && level === "주의") {
        nm.replaceAsync(NOTICE_KEY, { type: T.ErrorMessage, message: notice.message });
      }
    });
  }

  // ── B안: 메일 목록에 색 태그(범주) 붙이기 ─────────────────────────────
  // 설치 파일(manifest)이 taskpane.html?tags=1 로 열 때만 동작 (읽기·쓰기 권한 필요)
  var TAGS = /[?&]tags=1(&|$)/.test(location.search);
  var CAT = { "위험": "위험-열지말것", "주의": "주의-확인필요" };

  function showCatHint(name, err) {
    var h = document.getElementById("hint");
    h.innerHTML = "<b>목록 색 태그를 붙이지 못했습니다.</b><br>처음 한 번, 범주 2개를 만들어 주세요.<br>" +
      "메일을 오른쪽 클릭 → <b>범주 분류 → 새 범주</b><br>" +
      "① <b>위험-열지말것</b> (빨강) ② <b>주의-확인필요</b> (노랑)" +
      "<br><span style='font-size:11px'>(" + esc(name) + ": " + esc(err && (err.name || err.message)) + ")</span>";
    h.hidden = false;
  }

  function setCategory(item, level) {
    if (!TAGS || !item.categories) return;
    var OK = Office.AsyncResultStatus.Succeeded;
    var want = CAT[level] || null, all = [CAT["위험"], CAT["주의"]];
    item.categories.getAsync(function (r) {
      if (r.status !== OK) return;
      var have = (r.value || []).map(function (c) { return c.displayName; });
      var remove = all.filter(function (n) { return n !== want && have.indexOf(n) >= 0; });
      function add() {
        if (!want || have.indexOf(want) >= 0) return;
        item.categories.addAsync([want], function (a) { if (a.status !== OK) showCatHint(want, a.error); });
      }
      if (remove.length) item.categories.removeAsync(remove, add); else add();
    });
  }

  function render(state, item, reasons) {
    var box = document.getElementById("result"), det = document.getElementById("details");
    var map = {
      "위험": ["danger big", "⛔ 위험 · 열지 말 것", "유명 회사나 우리 회사를 흉내 낸 가짜 주소입니다. 링크와 첨부파일을 절대 누르지 말고 PI팀에 신고하세요."],
      "주의": ["warn big", "⚠ 주의 · 확인 필요", "외부에서 온 메일에 링크가 있습니다. 보낸 사람이 아는 거래처인지 확인하기 전에는 링크와 첨부파일을 누르지 마세요."],
      "정상": ["ok compact", "✓ 이상 없음", ""],
      "없음": ["wait compact", "메일을 선택하세요", ""],
      "오류": ["wait compact", "검사하지 못했습니다 · 메일을 다시 선택하세요", ""],
    };
    var m = map[state];
    box.className = "card " + m[0];
    box.innerHTML = "<h1>" + esc(m[1]) + "</h1>" + (m[2] ? "<p>" + esc(m[2]) + "</p>" : "");
    // 고정 안내는 메일을 고르기 전에만, 범주 안내는 다른 메일로 넘어가면 지움
    document.getElementById("tip").hidden = state !== "없음";
    document.getElementById("hint").hidden = true;
    if (!item || state === "없음" || state === "오류" || state === "정상") { det.innerHTML = ""; return; }
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
    document.getElementById("tip").hidden = true;
    document.getElementById("result").innerHTML = "<h1>검사 중…</h1>";

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
      setCategory(item, res.level);
    }).catch(function () {
      if (myRun === runId) render("오류");
    });
  }

  function start() {
    // 창을 고정(압정)해 두면 메일을 바꿔 선택할 때마다 다시 검사
    if (Office.context.mailbox.addHandlerAsync) {
      Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, run);
    }
    run();
  }

  Office.onReady(function () {
    // 화면(HTML)이 다 그려진 뒤에 검사 시작
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
    else start();
  });
})();

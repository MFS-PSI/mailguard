/* 메일 가드 판정 규칙
 * [규칙 1] 유명 도메인 철자 바꿔치기 → 위험 (무조건 악성)
 * [규칙 2] 외부 메일에 링크          → 주의
 * 메일 내용은 이 브라우저 안에서만 검사하며 어디로도 보내지 않습니다.
 */
var MailGuardRules = (function () {
  "use strict";

  // "기준 이름": { names: 보낸 사람 이름에 쓰일 수 있는 이름, official: 진짜 도메인 }
  var BRANDS = {
    coupang:   { names: ["쿠팡", "coupang"], official: ["coupang.com", "coupangcorp.com", "coupang.net", "coupangeats.com"] },
    nexon:     { names: ["넥슨", "nexon"], official: ["nexon.com", "nexon.co.kr", "nexon.net"] },
    naver:     { names: ["네이버", "naver"], official: ["naver.com", "navercorp.com", "naver.net"] },
    kakao:     { names: ["카카오", "kakao"], official: ["kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com", "daum.net"] },
    daum:      { names: ["daum"], official: ["daum.net", "kakao.com"] },
    google:    { names: ["구글", "google"], official: ["google.com", "gmail.com", "youtube.com", "google.co.kr"] },
    microsoft: { names: ["마이크로소프트", "microsoft", "office 365"],
                 official: ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com",
                            "office365.com", "sharepoint.com", "hotmail.com", "powerbi.com"] },
    apple:     { names: ["애플", "apple", "icloud"], official: ["apple.com", "icloud.com"] },
    samsung:   { names: ["삼성", "samsung"], official: ["samsung.com", "samsungcard.com", "samsungfire.com", "samsunglife.com", "samsungpop.com", "samsungsds.com"] },
    amazon:    { names: ["아마존", "amazon"], official: ["amazon.com", "amazon.co.jp", "amazonaws.com", "amazon.co.uk"] },
    paypal:    { names: ["페이팔", "paypal"], official: ["paypal.com"] },
    netflix:   { names: ["넷플릭스", "netflix"], official: ["netflix.com"] },
    ncsoft:    { names: ["엔씨소프트", "ncsoft"], official: ["ncsoft.com", "plaync.com"] },
    netmarble: { names: ["넷마블", "netmarble"], official: ["netmarble.com", "netmarble.net"] },
    kbstar:    { names: ["국민은행", "kb국민"], official: ["kbstar.com", "kbcard.com", "kbfg.com"] },
    shinhan:   { names: ["신한은행", "신한카드"], official: ["shinhan.com", "shinhancard.com"] },
    wooribank: { names: ["우리은행"], official: ["wooribank.com", "wooricard.com"] },
    hanabank:  { names: ["하나은행"], official: ["hanabank.com", "kebhana.com", "hanacard.co.kr"] },
    cjlogistics: { names: ["cj대한통운", "대한통운"], official: ["cjlogistics.com", "cjlogistics.co.kr"] },
    epost:     { names: ["우체국"], official: ["epost.go.kr", "koreapost.go.kr"] },
    dhl:       { names: ["dhl"], official: ["dhl.com", "dhl.co.kr"] },
    fedex:     { names: ["fedex", "페덱스"], official: ["fedex.com"] },
    gmarket:   { names: ["지마켓", "g마켓"], official: ["gmarket.co.kr"] },
    "11st":    { names: ["11번가"], official: ["11st.co.kr"] },
    docusign:  { names: ["docusign"], official: ["docusign.com", "docusign.net"] },
    adobe:     { names: ["adobe", "어도비"], official: ["adobe.com"] },
    linkedin:  { names: ["linkedin", "링크드인"], official: ["linkedin.com"] },
    hometax:   { names: ["국세청", "홈택스"], official: ["hometax.go.kr", "nts.go.kr"] },
  };

  var MULTI_SUFFIXES = ["co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr", "pe.kr", "co.jp", "ne.jp", "or.jp",
    "co.uk", "org.uk", "com.cn", "com.tw", "com.hk", "com.au", "com.sg", "com.vn", "com.br"];

  // 회사마다 '회사이름.서비스주소'를 받아 쓰는 업무용 서비스 (예: company.atlassian.net, company.sharepoint.com)
  // 여기서는 앞쪽 회사 이름을 '하위 주소 속임수'로 보지 않음
  var TENANT_PARENTS = ["atlassian.net", "sharepoint.com", "daouoffice.com", "slack.com", "zendesk.com",
    "service-now.com", "webex.com", "zoom.us", "notion.site", "monday.com", "box.com", "okta.com", "salesforce.com",
    "force.com", "my.site.com", "workday.com", "freshdesk.com", "kr.daouoffice.com"];

  // 'coupang.com.evil.net' 처럼 이름 뒤에 .com/.co.kr 등을 붙여 진짜 주소처럼 보이게 하는 경우
  var TLD_LIKE = ["com", "net", "org", "co", "kr", "go", "or", "ac", "jp", "io"];

  var ATTACH_EXTS = [".pdf", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".rtf"];

  function domainOf(addr) {
    addr = (addr || "").trim().toLowerCase();
    var i = addr.lastIndexOf("@");
    return i >= 0 ? addr.slice(i + 1) : "";
  }

  function endsWithDomain(domain, base) {
    return domain === base || domain.slice(-(base.length + 1)) === "." + base;
  }

  function hostOf(url) {
    var m = /^[a-z][a-z0-9+.-]*:\/\/([^\/:?#]+)/i.exec((url || "").trim());
    return m ? m[1].toLowerCase() : "";
  }

  // 'mail.cuupang.co.kr' -> { label: 'cuupang', subs: ['mail'] }
  function splitDomain(domain) {
    var parts = domain.toLowerCase().replace(/^\.+|\.+$/g, "").split(".").filter(Boolean);
    if (parts.length < 2) return { label: domain, subs: [] };
    var n = parts.length >= 3 && MULTI_SUFFIXES.indexOf(parts.slice(-2).join(".")) >= 0 ? 3 : 2;
    return { label: parts[parts.length - n], subs: parts.slice(0, parts.length - n) };
  }

  function editDistance(a, b) {
    var prev = [], cur, i, j;
    for (j = 0; j <= b.length; j++) prev.push(j);
    for (i = 1; i <= a.length; i++) {
      cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  // 눈속임 글자를 원래 글자로: 0→o, 1→l, rn→m, vv→w, 하이픈 제거
  function normalizeLabel(label) {
    return label.toLowerCase()
      .split("rn").join("m").split("vv").join("w")
      .split("0").join("o").split("1").join("l").split("3").join("e").split("5").join("s")
      .split("-").join("");
  }

  function isOfficial(domain, info) {
    return info.official.some(function (o) { return endsWithDomain(domain, o); });
  }

  function brandsWithOwnCompany(ctx) {
    // 우리 회사 도메인도 사칭 감시 대상에 자동 추가 (예: company.com → cornpany.com 탐지)
    var b = {}, k;
    for (k in BRANDS) b[k] = BRANDS[k];
    ctx.internalDomains.forEach(function (d) {
      var label = splitDomain(d).label;
      if (label && label.length >= 3 && !b[label]) {
        b[label] = { names: [], official: ctx.internalDomains.concat(ctx.trustedSystemParents) };
      }
    });
    return b;
  }

  function brandLookalike(domain, brands) {
    if (!domain || domain.indexOf(".") < 0) return null;
    var sd = splitDomain(domain), label = sd.label, norm = normalizeLabel(label);
    for (var brand in brands) {
      var info = brands[brand];
      if (isOfficial(domain, info)) continue;
      var at = sd.subs.indexOf(brand);
      if (at >= 0) {
        var fakeTld = TLD_LIKE.indexOf(sd.subs[at + 1]) >= 0; // coupang.com.evil.net
        var tenant = TENANT_PARENTS.some(function (p) { return endsWithDomain(domain, p); });
        if (fakeTld || !tenant) return brand + " 사칭(하위 주소 속임수): " + domain;
      }
      if (norm.length < 3) continue;
      if (norm === brand || label === brand) return brand + " 사칭(진짜가 아닌 도메인): " + domain;
      if (brand.length < 5) continue; // dhl, daum 같은 짧은 이름은 정확히 같을 때만
      var limit = brand.length < 8 ? 1 : 2;
      if (Math.abs(norm.length - brand.length) <= limit && editDistance(norm, brand) <= limit) {
        return brand + " 철자 바꿔치기: " + domain;
      }
      if (norm.indexOf(brand) >= 0) return brand + " 이름을 섞은 가짜 도메인: " + domain;
    }
    return null;
  }

  function displayBrandSpoof(display, domain, brands) {
    var low = (display || "").toLowerCase();
    for (var brand in brands) {
      var info = brands[brand];
      for (var i = 0; i < info.names.length; i++) {
        var name = info.names[i];
        if (name && low.indexOf(name.toLowerCase()) >= 0 && !isOfficial(domain, info)) {
          return "이름은 '" + name + "'인데 보낸 주소가 공식 도메인이 아님: " + domain;
        }
      }
    }
    return null;
  }

  // 클릭 가능한 링크 주소 목록 (HTML 링크 + 본문에 적힌 주소)
  function extractLinks(html, text) {
    var urls = [], m, re;
    re = /<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)/gi;
    while ((m = re.exec(html || ""))) urls.push(m[1].trim());
    re = /<(?:area|form)\b[^>]*?(?:href|action)\s*=\s*["']?([^"'\s>]+)/gi;
    while ((m = re.exec(html || ""))) urls.push(m[1].trim());
    re = /(?:https?:\/\/|www\.)[^\s<>"'\)\]]+/gi;
    while ((m = re.exec(text || ""))) urls.push(m[0].indexOf("://") >= 0 ? m[0] : "http://" + m[0]);
    return urls
      .map(function (u) { return u.replace(/&amp;/g, "&"); })
      .filter(function (u) { return !/^(mailto:|tel:|cid:|#|about:)/i.test(u); });
  }

  function isSafeLinkHost(host, ctx) {
    return ctx.safeLinkDomains.some(function (d) { return endsWithDomain(host, d); });
  }

  /* ── 첨부 문서 안의 링크 (bytes: Uint8Array) ─────────────────────── */
  function bytesToLatin1(bytes) {
    var s = "", CH = 0x8000;
    for (var i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return s;
  }

  function latin1ToBytes(s) {
    var b = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
    return b;
  }

  function linksInPdf(bytes) {
    var raw = bytesToLatin1(bytes), chunks = [raw], found = [], m;
    var re = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
    while ((m = re.exec(raw))) {
      try { if (window.pako) chunks.push(bytesToLatin1(window.pako.inflate(latin1ToBytes(m[1])))); } catch (e) { /* 압축 아님 */ }
    }
    chunks.forEach(function (c) {
      var r = /\/URI\s*\(([^)]+)\)/g, mm;
      while ((mm = r.exec(c))) found.push(mm[1]);
      if (/\/Launch|\/SubmitForm/.test(c)) found.push("(PDF 실행/전송 동작)");
    });
    return Promise.resolve(found);
  }

  function linksInOoxml(bytes) {
    if (!window.JSZip) return Promise.resolve([]);
    return window.JSZip.loadAsync(bytes).then(function (zip) {
      var jobs = [];
      zip.forEach(function (path, f) {
        if (/\.rels$/.test(path)) jobs.push(f.async("string"));
      });
      return Promise.all(jobs).then(function (texts) {
        var found = [];
        texts.forEach(function (t) {
          var r = /<Relationship\b[^>]*>/g, m;
          while ((m = r.exec(t))) {
            if (/TargetMode="External"/.test(m[0])) {
              var tg = /Target="(https?:\/\/[^"]+)"/.exec(m[0]);
              if (tg) found.push(tg[1]);
            }
          }
        });
        return found;
      });
    }).catch(function () { return []; });
  }

  function linksInRtf(bytes) {
    var raw = bytesToLatin1(bytes), found = [], m, r = /HYPERLINK\s+"(https?:\/\/[^"]+)"/g;
    while ((m = r.exec(raw))) found.push(m[1]);
    return Promise.resolve(found);
  }

  function linksInAttachment(name, bytes) {
    var ext = (/\.[^.]+$/.exec(name.toLowerCase()) || [""])[0];
    if (ext === ".pdf") return linksInPdf(bytes);
    if (ext === ".rtf") return linksInRtf(bytes);
    if (ATTACH_EXTS.indexOf(ext) >= 0) return linksInOoxml(bytes);
    return Promise.resolve([]);
  }

  /* ── 판정 ───────────────────────────────────────────────────────── */
  function makeContext(config, userEmail) {
    var internal = (config.internalDomains || []).filter(Boolean).map(function (d) { return d.toLowerCase(); });
    if (!internal.length && userEmail) internal = [domainOf(userEmail)];
    var trusted = (config.trustedSystemDomains || []).map(function (d) { return d.toLowerCase(); });
    var parents = trusted.map(function (d) { var p = d.split("."); return p.slice(-3).join("."); });
    return {
      internalDomains: internal,
      trustedSystemDomains: trusted,
      trustedSystemParents: parents,
      safeLinkDomains: (config.safeLinkDomains || []).map(function (d) { return d.toLowerCase(); }),
    };
  }

  function isExternal(domain, ctx) {
    if (!domain) return false;
    if (ctx.internalDomains.some(function (d) { return endsWithDomain(domain, d); })) return false;
    if (ctx.trustedSystemDomains.indexOf(domain) >= 0) return false;
    return true;
  }

  /* mail = { fromAddress, fromName, html, text, attachmentLinks: [{name, links}] }
   * 반환: { level: "위험"|"주의"|"정상", reasons: [...], external: bool } */
  function analyze(mail, ctx) {
    var brands = brandsWithOwnCompany(ctx);
    var dom = domainOf(mail.fromAddress);
    var external = isExternal(dom, ctx);
    var links = extractLinks(mail.html, mail.text);
    var r1 = [], r2 = [], why, i;

    // [규칙 1] 유명 도메인 철자 바꿔치기 — 보낸 주소, 보낸 사람 이름, 링크 주소
    if (ctx.trustedSystemDomains.indexOf(dom) < 0) {
      why = brandLookalike(dom, brands);
      if (why) r1.push("보낸 주소 " + why);
    }
    if (external) {
      why = displayBrandSpoof(mail.fromName, dom, brands);
      if (why) r1.push(why);
    }
    for (i = 0; i < links.length; i++) {
      why = brandLookalike(hostOf(links[i]), brands);
      if (why) { r1.push("링크 주소 " + why); break; }
    }

    // [규칙 2] 외부 메일에 링크 (본문 + 첨부 문서 안)
    if (external) {
      var risky = links.filter(function (u) { return !isSafeLinkHost(hostOf(u), ctx); });
      if (risky.length) {
        var hosts = [];
        risky.forEach(function (u) { var h = hostOf(u) || u.slice(0, 40); if (hosts.indexOf(h) < 0) hosts.push(h); });
        r2.push("외부 메일 본문에 링크 " + risky.length + "개: " + hosts.slice(0, 3).join(", "));
      }
      (mail.attachmentLinks || []).forEach(function (a) {
        var al = a.links.filter(function (u) { return !isSafeLinkHost(hostOf(u), ctx); });
        if (al.length) r2.push("첨부 문서 안에 링크 " + al.length + "개: " + a.name);
      });
    }

    var level = r1.length ? "위험" : r2.length ? "주의" : "정상";
    return {
      level: level,
      reasons: r1.map(function (s) { return "[규칙1] " + s; }).concat(r2.map(function (s) { return "[규칙2] " + s; })),
      external: external,
    };
  }

  return {
    analyze: analyze,
    makeContext: makeContext,
    linksInAttachment: linksInAttachment,
    domainOf: domainOf,
    isExternal: isExternal,
    ATTACH_EXTS: ATTACH_EXTS,
    // 시험용
    _brandLookalike: function (d, ctx) { return brandLookalike(d, brandsWithOwnCompany(ctx)); },
  };
})();

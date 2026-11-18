/* 메일 가드 설정 */
var MAILGUARD_CONFIG = {
  // 우리 회사 메일 도메인. 비워 두면 로그인한 사람의 메일 도메인을 자동으로 사용
  internalDomains: [],

  // 회사 시스템 발신자(예: 스팸 차단 리포트) — 외부 메일로 보지 않음
  trustedSystemDomains: [],

  // [규칙 2] 예외로 허용할 링크 도메인 (여기 적은 도메인으로만 가는 링크는 무시)
  safeLinkDomains: [],

  // [규칙 2] 외부 메일 첨부 문서(PDF·워드·엑셀·파워포인트) 안의 링크도 검사
  scanAttachmentLinks: true,
};
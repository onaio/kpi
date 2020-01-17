const ZEBRA_LOGIN_URL = "http://localhost:3001/login";

export function getAuthUrl(url) {
  return ZEBRA_LOGIN_URL + "?return_url=" + url;
}

export function getZebraLoginUrl() {
  return ZEBRA_LOGIN_URL;
}

const SENTY_DSN = "{{kpi_raven_js_dsn}}";

export const WEB_PAGE_TITLE = 'Ona';

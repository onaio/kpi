const ZEBRA_LOGIN_URL = "http://localhost:3005/login";

export function getAuthUrl(url) {
  return ZEBRA_LOGIN_URL + "?return_url=" + url;
}

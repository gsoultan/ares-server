// The session token the server handed out at sign-in. It is kept in the
// browser so a reload does not sign the person out, and it is sent with every
// call so the server knows who is asking.

const STORAGE_KEY = "ares.session";

// Fired when the server stops accepting the token, so the app can show the
// sign-in screen again.
export const SIGNED_OUT_EVENT = "ares:signed-out";

let current: string | null = null;

export function readToken(): string {
  if (current !== null) return current;
  try {
    current = localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    current = "";
  }
  return current;
}

export function writeToken(token: string) {
  current = token;
  try {
    if (token) localStorage.setItem(STORAGE_KEY, token);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Without storage the session simply ends with the tab.
  }
}

import { Code, ConnectError, createClient, type Interceptor } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { ControlPlane } from "./gen/ares/v1/ares_pb.js";
import { readToken, SIGNED_OUT_EVENT } from "./lib/token.ts";

// The control-plane origin. Same-origin by default (dev proxy forwards Connect
// calls to the Go server); override with VITE_ARES_URL for a split deployment.
const baseUrl =
  (import.meta.env.VITE_ARES_URL as string | undefined) ??
  (typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8080");

// Every call carries the session token. When the server says the token is no
// longer good, the app is told so it can ask the person to sign in again.
const withSession: Interceptor = (next) => async (req) => {
  const token = readToken();
  if (token) req.header.set("Authorization", `Bearer ${token}`);
  try {
    return await next(req);
  } catch (err) {
    if (token && err instanceof ConnectError && err.code === Code.Unauthenticated) {
      window.dispatchEvent(new Event(SIGNED_OUT_EVENT));
    }
    throw err;
  }
};

const transport = createConnectTransport({ baseUrl, interceptors: [withSession] });

// One typed client for the whole app, generated from the same protos as the
// Go backend, so the two sides cannot drift.
export const control = createClient(ControlPlane, transport);

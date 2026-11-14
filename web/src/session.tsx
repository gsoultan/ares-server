import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Code, ConnectError } from "@connectrpc/connect";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "./client.ts";
import type { UserInfo } from "./gen/ares/v1/ares_pb.ts";
import { readToken, SIGNED_OUT_EVENT, writeToken } from "./lib/token.ts";
import { useTenant } from "./tenant.tsx";

// The signed-in person. The server keeps the session; the browser only holds
// the token it was given at sign-in, and asks the server who it belongs to on
// every load.

const ROLES: Record<string, string> = {
  superadmin: "Super administrator",
  owner: "Owner",
  admin: "Administrator",
  member: "Member",
};

export function roleName(role: string): string {
  return ROLES[role] ?? role;
}

type SessionValue = {
  // undefined while the server is being asked, null when nobody is signed in.
  user: UserInfo | null | undefined;
  // Set when the server could not be asked at all.
  error: unknown;
  signIn: (token: string, user: UserInfo) => void;
  signOut: () => void;
};

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { tenantId, setTenantId } = useTenant();
  const [token, setToken] = useState<string>(readToken);

  const me = useQuery({
    queryKey: ["me", token],
    queryFn: () => control.currentUser({ token }),
    enabled: token !== "",
    staleTime: 60_000,
    retry: (count, err) =>
      !(err instanceof ConnectError && err.code === Code.Unauthenticated) && count < 1,
  });

  // A token the server no longer accepts (expired or signed out elsewhere).
  const rejected = me.error instanceof ConnectError && me.error.code === Code.Unauthenticated;
  useEffect(() => {
    if (!rejected) return;
    writeToken("");
    setToken("");
  }, [rejected]);

  // Any call can discover that the session has ended.
  useEffect(() => {
    const ended = () => {
      writeToken("");
      setToken("");
      qc.clear();
    };
    window.addEventListener(SIGNED_OUT_EVENT, ended);
    return () => window.removeEventListener(SIGNED_OUT_EVENT, ended);
  }, [qc]);

  // Someone who belongs to one workspace always works in that workspace. The
  // server enforces this; the app just asks for the right one.
  const home = me.data && me.data.role !== "superadmin" ? me.data.tenantId : "";
  useEffect(() => {
    if (home && home !== tenantId) setTenantId(home);
  }, [home, tenantId, setTenantId]);

  const signIn = (next: string, user: UserInfo) => {
    writeToken(next);
    qc.setQueryData(["me", next], user);
    if (user.tenantId) setTenantId(user.tenantId);
    setToken(next);
  };

  const signOut = () => {
    const old = token;
    writeToken("");
    setToken("");
    qc.clear();
    if (old) void control.logout({ token: old }).catch(() => undefined);
  };

  const user = token === "" || rejected ? null : me.data;
  const error = token !== "" && !rejected ? me.error : null;

  return (
    <SessionContext.Provider value={{ user, error, signIn, signOut }}>{children}</SessionContext.Provider>
  );
}

export function useSession(): SessionValue {
  const v = useContext(SessionContext);
  if (!v) throw new Error("useSession must be used within a SessionProvider");
  return v;
}

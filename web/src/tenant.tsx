import { createContext, useContext, useState, type ReactNode } from "react";

// A workspace (tenant) is the isolation boundary for a client's engagements.
// The selected workspace is sent on every control-plane call, so the UI only
// ever shows and touches the current client's data. The choice is a per-viewer
// convenience, remembered in localStorage; the server enforces the isolation.

const STORAGE_KEY = "ares.tenant";

// DefaultTenantId mirrors the server's built-in workspace id (a reserved
// UUIDv7-form value; see internal/tenant.DefaultID). An empty id on the wire
// also resolves to it, but sending it explicitly keeps the UI honest.
export const DefaultTenantId = "00000000-0000-7000-8000-000000000000";

type TenantValue = {
  tenantId: string;
  setTenantId: (id: string) => void;
};

const TenantContext = createContext<TenantValue | null>(null);

function readStored(): string {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    // Ignore ids from before workspaces used UUIDs (the old "tnt-*" scheme).
    if (!v || v.startsWith("tnt-")) return DefaultTenantId;
    return v;
  } catch {
    return DefaultTenantId;
  }
}

export function TenantProvider({ children }: { children: ReactNode }) {
  const [tenantId, setTenantIdState] = useState<string>(readStored);

  const setTenantId = (id: string) => {
    setTenantIdState(id);
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {
      // Storage is a convenience only; ignore private-mode/blocked failures.
    }
  };

  return (
    <TenantContext.Provider value={{ tenantId, setTenantId }}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant(): TenantValue {
  const v = useContext(TenantContext);
  if (!v) throw new Error("useTenant must be used within a TenantProvider");
  return v;
}

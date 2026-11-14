import "@mantine/core/styles.css";
import "@fontsource-variable/inter";
import "./index.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MantineProvider } from "@mantine/core";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { theme } from "./theme.ts";
import { queryClient } from "./lib/queryClient.ts";
import { router } from "./router.tsx";
import { SessionProvider } from "./session.tsx";
import { TenantProvider } from "./tenant.tsx";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("missing #root");

createRoot(rootEl).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="light">
      <QueryClientProvider client={queryClient}>
        <TenantProvider>
          <SessionProvider>
            <RouterProvider router={router} />
          </SessionProvider>
        </TenantProvider>
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);

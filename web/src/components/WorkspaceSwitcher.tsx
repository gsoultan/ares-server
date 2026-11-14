import { useState } from "react";
import { ActionIcon, Button, Group, Modal, Select, Stack, TextInput, Tooltip } from "@mantine/core";
import { IconBuilding, IconPlus } from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { control } from "../client.ts";
import { useTenant } from "../tenant.tsx";

// WorkspaceSwitcher picks the active client workspace and creates new ones.
// Switching workspaces returns to the engagement list, since an engagement open
// in one workspace does not exist in another.
export function WorkspaceSwitcher() {
  const { tenantId, setTenantId } = useTenant();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [opened, setOpened] = useState(false);
  const [name, setName] = useState("");

  const tenants = useQuery({
    queryKey: ["tenants"],
    queryFn: () => control.listTenants({}),
    staleTime: 30_000,
  });

  const create = useMutation({
    mutationFn: (n: string) => control.createTenant({ name: n }),
    onSuccess: async (t) => {
      setOpened(false);
      setName("");
      await qc.invalidateQueries({ queryKey: ["tenants"] });
      if (t.id) {
        setTenantId(t.id);
        void navigate({ to: "/" });
      }
    },
  });

  const options = (tenants.data?.tenants ?? [])
    .map((t) => ({ value: t.id, label: t.name }))
    .sort((a, b) => a.label.localeCompare(b.label));

  return (
    <>
      <Group gap="xs" wrap="nowrap">
        <Select
          style={{ flex: 1, minWidth: 0 }}
          aria-label="Client workspace"
          leftSection={<IconBuilding size={16} />}
          data={options}
          value={tenantId}
          allowDeselect={false}
          checkIconPosition="right"
          placeholder={tenants.isLoading ? "Loading…" : "Workspace"}
          onChange={(v) => {
            if (v && v !== tenantId) {
              setTenantId(v);
              void navigate({ to: "/" });
            }
          }}
        />
        <Tooltip label="Add a client workspace">
          <ActionIcon
            variant="default"
            size="lg"
            aria-label="Add a client workspace"
            onClick={() => setOpened(true)}
          >
            <IconPlus size={18} />
          </ActionIcon>
        </Tooltip>
      </Group>

      <Modal opened={opened} onClose={() => setOpened(false)} title="Add a client workspace">
        <Stack>
          <TextInput
            label="Client name"
            description="Each client gets a separate workspace. Their engagements are never mixed."
            placeholder="Acme Corp"
            value={name}
            onChange={(ev) => setName(ev.currentTarget.value)}
            data-autofocus
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setOpened(false)}>
              Cancel
            </Button>
            <Button
              loading={create.isPending}
              disabled={name.trim() === ""}
              onClick={() => create.mutate(name.trim())}
            >
              Add workspace
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

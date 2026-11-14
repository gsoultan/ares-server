import { useState } from "react";
import { Button, Group, Modal, Stack, TextInput } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { control } from "../../client.ts";
import { errorText } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote } from "../../ui/index.tsx";

// NewEngagement is the button that starts an engagement, with the one question
// it needs. A new engagement opens straight on its setup.
export function NewEngagement() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { tenantId } = useTenant();
  const [opened, setOpened] = useState(false);
  const [name, setName] = useState("");

  const create = useMutation({
    mutationFn: (engName: string) => control.createEngagement({ name: engName, tenantId }),
    onSuccess: (e) => {
      setOpened(false);
      setName("");
      void qc.invalidateQueries({ queryKey: ["engagements", tenantId] });
      if (e.id) void navigate({ to: "/engagements/$id", params: { id: e.id } });
    },
  });

  const close = () => {
    setOpened(false);
    create.reset();
  };
  const submit = () => {
    if (name.trim() !== "") create.mutate(name.trim());
  };

  return (
    <>
      <Button leftSection={<IconPlus size={16} />} onClick={() => setOpened(true)}>
        New engagement
      </Button>
      <Modal opened={opened} onClose={close} title="New engagement">
        <Stack>
          <TextInput
            label="Name"
            description="Something your team will recognise, such as the client and what is being tested."
            placeholder="Acme public website"
            value={name}
            onChange={(ev) => setName(ev.currentTarget.value)}
            onKeyDown={(ev) => ev.key === "Enter" && submit()}
            data-autofocus
          />
          {create.isError && (
            <ErrorNote title="Could not create the engagement">{errorText(create.error)}</ErrorNote>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button loading={create.isPending} disabled={name.trim() === ""} onClick={submit}>
              Create engagement
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

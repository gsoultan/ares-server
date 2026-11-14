import { Box, Card, Group, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { PageHeader, Section } from "../ui/index.tsx";

const YEAR = 2026;
export const COPYRIGHT_HOLDER = "Gembit Soultan Shirazi";
export const COPYRIGHT_LINE = `Copyright © ${YEAR} ${COPYRIGHT_HOLDER}. All rights reserved.`;

const WHAT_IT_DOES = [
  {
    title: "Tests only what is allowed",
    detail: "Nothing runs until a scope is set and signed permission is on file. Anything outside the scope is skipped.",
  },
  {
    title: "Explains what it finds",
    detail: "Each weakness says what was found, what it means and how to fix it, with the proof behind it.",
  },
  {
    title: "Shows if defenders noticed",
    detail: "Record what your security tools and people did, and see how ready you are for well-known attacks.",
  },
  {
    title: "Keeps a record you can trust",
    detail: "Every action is written to an activity log that cannot be edited and is checked for changes.",
  },
];

// AboutPage says what Ares is, and who owns it.
export function AboutPage() {
  return (
    <Stack gap="lg">
      <PageHeader title="About" description="What Ares is, and who owns it." />

      <Card>
        <Group gap="md" wrap="nowrap" align="flex-start">
          <img src="/icon.svg" alt="" width={48} height={48} />
          <Box>
            <Title order={2}>Ares</Title>
            <Text c="dimmed" size="sm">
              Authorized security testing
            </Text>
            <Text mt="sm" maw={640}>
              Ares is a self-hosted platform for authorized security testing. A security team uses
              it to assess systems they are responsible for, or have written permission to test. It
              maps what is exposed, runs checks that change nothing, records what the defenders
              noticed, and reports what to fix.
            </Text>
          </Box>
        </Group>
      </Card>

      <Section title="What it does">
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
          {WHAT_IT_DOES.map((w) => (
            <Box key={w.title}>
              <Text fw={600}>{w.title}</Text>
              <Text size="sm" c="dimmed">
                {w.detail}
              </Text>
            </Box>
          ))}
        </SimpleGrid>
      </Section>

      <Section title="Copyright and license">
        <Text fw={600}>{COPYRIGHT_LINE}</Text>
        <Text maw={640}>
          Ares is commercial, proprietary software under the Ares Commercial Proprietary Business
          License. It is licensed, not sold. A business may use it only under a signed commercial
          agreement with {COPYRIGHT_HOLDER}, within the term, number of users and installations that
          agreement sets. Without such an agreement, no right to use Ares exists.
        </Text>
        <Text maw={640}>
          Ares, including its source code, design, documentation and name, stays the property of{" "}
          {COPYRIGHT_HOLDER}. No part of it may be copied, changed, shared, sold or used to make
          other products without the owner's written permission. The full terms are in the LICENSE
          file that comes with the software.
        </Text>
        <Text maw={640}>
          Ares is provided for authorized security testing only. Use it only on systems you own or
          have explicit written permission to test. It is provided as it is, without any warranty,
          and the owner is not liable for damage that comes from using it.
        </Text>
      </Section>
    </Stack>
  );
}

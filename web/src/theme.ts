import {
  Badge,
  Button,
  Card,
  createTheme,
  Modal,
  NavLink,
  Select,
  Table,
  Textarea,
  TextInput,
  Tooltip,
  type MantineColorsTuple,
} from "@mantine/core";

// The Ares design system lives here. Every colour, size, radius and component
// default the app uses is defined in this file (plus the few CSS variables in
// index.css). Screens compose the shared pieces in src/ui and never set raw
// colours or pixel sizes of their own. See web/DESIGN.md.

// Brand: one confident indigo, used only for the primary action and links.
const brand: MantineColorsTuple = [
  "#eef2ff",
  "#e0e7ff",
  "#c7d2fe",
  "#a5b4fc",
  "#818cf8",
  "#6366f1",
  "#4f46e5",
  "#4338ca",
  "#3730a3",
  "#312e81",
];

// Neutrals: a cool slate, so surfaces read as calm rather than muddy.
const slate: MantineColorsTuple = [
  "#f8fafc",
  "#f1f5f9",
  "#e2e8f0",
  "#cbd5e1",
  "#94a3b8",
  "#64748b",
  "#475569",
  "#334155",
  "#1e293b",
  "#0f172a",
];

const dark: MantineColorsTuple = [
  "#d5dbe6",
  "#aab3c5",
  "#8690a6",
  "#5f6980",
  "#343d52",
  "#262e40",
  "#181f2e",
  "#111724",
  "#0b101a",
  "#070a11",
];

export const theme = createTheme({
  primaryColor: "brand",
  primaryShade: { light: 6, dark: 5 },
  colors: { brand, gray: slate, dark },
  autoContrast: true,

  fontFamily:
    '"Inter Variable", Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
  fontFamilyMonospace:
    'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',

  // Type scale: 12 caption · 13 small · 14 body · 16 lead · 20 large.
  fontSizes: { xs: "12px", sm: "13px", md: "14px", lg: "16px", xl: "20px" },
  lineHeights: { xs: "1.45", sm: "1.5", md: "1.55", lg: "1.5", xl: "1.35" },
  headings: {
    fontWeight: "650",
    sizes: {
      h1: { fontSize: "26px", lineHeight: "1.25" },
      h2: { fontSize: "18px", lineHeight: "1.35" },
      h3: { fontSize: "15px", lineHeight: "1.4" },
    },
  },

  // Spacing: a 4px grid. xs 8 · sm 12 · md 16 · lg 24 · xl 32.
  spacing: { xs: "8px", sm: "12px", md: "16px", lg: "24px", xl: "32px" },
  radius: { xs: "4px", sm: "6px", md: "8px", lg: "12px", xl: "16px" },
  defaultRadius: "md",
  shadows: {
    xs: "0 1px 2px rgba(15, 23, 42, 0.05)",
    sm: "0 1px 3px rgba(15, 23, 42, 0.08), 0 1px 2px rgba(15, 23, 42, 0.04)",
    md: "0 8px 24px rgba(15, 23, 42, 0.10)",
  },

  components: {
    Button: Button.extend({ defaultProps: { size: "sm" } }),
    // Badges are sentence case and quiet; colour carries the meaning.
    Badge: Badge.extend({
      defaultProps: { variant: "light", radius: "sm", size: "md" },
      styles: { root: { textTransform: "none", fontWeight: 600, letterSpacing: 0 } },
    }),
    Card: Card.extend({
      defaultProps: { withBorder: true, radius: "lg", padding: "lg", shadow: "xs" },
    }),
    Modal: Modal.extend({
      defaultProps: { centered: true, radius: "lg", padding: "lg" },
      styles: { title: { fontWeight: 650, fontSize: "16px" } },
    }),
    NavLink: NavLink.extend({
      defaultProps: { variant: "light" },
      styles: { root: { borderRadius: 8, fontWeight: 500 }, label: { fontSize: 14 } },
    }),
    TextInput: TextInput.extend({ defaultProps: { size: "sm" } }),
    Textarea: Textarea.extend({ defaultProps: { size: "sm" } }),
    Select: Select.extend({ defaultProps: { size: "sm" } }),
    Table: Table.extend({
      defaultProps: { verticalSpacing: "sm", horizontalSpacing: "lg" },
    }),
    Tooltip: Tooltip.extend({ defaultProps: { withArrow: true, multiline: true, maw: 300 } }),
  },
});

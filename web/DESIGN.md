# Ares design system

The rules every Ares screen follows. The values live in `src/theme.ts` and the
few surface variables in `src/index.css`; the shared pieces live in
`src/ui/index.tsx`; all wording lives in `src/lib/labels.ts`. A screen composes
those and sets no colours, sizes or status words of its own.

## Principles

1. **Plain language first.** No ids, module names, status codes or raw errors in
   the page. "Run test", not "Dispatch job". "Stopped", not "halted".
2. **One primary action per screen.** It is the only solid indigo button.
3. **Colour means something.** Indigo is action. Green, orange and red are
   state. Everything else is neutral.
4. **Details on request.** Proof, advanced settings and exercise steps are one
   click away, never in the way.
5. **Every region has four states**: loading, empty, error and content.

## Foundations

| Token | Values |
| --- | --- |
| Type (Inter) | 26 page title · 18 section title · 15 item title · 14 body · 13 small · 12 caption |
| Weight | 650 titles · 600 labels and emphasis · 400 body |
| Spacing (4px grid) | 8 · 12 · 16 · 24 · 32. Sections are 24 apart, card padding is 24 |
| Radius | 12 section cards · 8 controls and inner cards · 6 badges |
| Page | one centred column, 1040 wide, 56 header |
| Brand | indigo `#4f46e5` |
| Neutrals | slate; canvas `#f5f7fa`, surface `#ffffff`, line `#e2e8f0` |
| Tones | good teal · warn orange · bad red · neutral slate |
| Severity | Critical solid red · High red · Medium orange · Low yellow · Note grey |

Light is the default; dark mode uses the same tokens (toggle in the header).

## Components (`src/ui`)

| Piece | Use |
| --- | --- |
| `PageHeader` | The one heading of a screen: back link, title, status, summary, actions |
| `Section` | The one card content sits in: title, one line of help, optional aside |
| `StatusBadge` / `ToneBadge` | State in words, with a hint on hover |
| `SeverityBadge` | How serious a finding is |
| `Stat` | A headline number with its caption |
| `LoadingState` / `EmptyState` / `ErrorNote` / `InfoNote` | The non-content states |
| `FindingCard` | Severity, title, address, then What we found / What it means / How to fix it, with proof behind "Show proof" |

## Screens

- **Engagements**: a list. Each row is a link: name, status, created.
- **Engagement**: header with status and the two engagement-wide actions
  (Download report, Stop testing), then three tabs.
  - **Testing**: two setup steps while setting up; the test form and its
    results once permission is on file.
  - **Defenses**: what the defenders did per technique, then breach exercises.
  - **Activity log**: the tamper-evident record with one verdict.

## Adding to it

New wording goes in `labels.ts`. A new status or outcome picks one of the four
tones. A new block of content is a `Section`. If a value is missing from the
theme, add it to the theme rather than writing it inline.

## Screens

The menu on the left is the map of the product.

| Menu | What it answers |
| --- | --- |
| Overview | Where do we stand, what to fix first, what is waiting on me |
| Engagements | The rounds of testing, with status, open findings and last test |
| Engagement: Scope and permission | What may be tested and who allowed it |
| Engagement: Target profile | What the target is built with, and which tests that makes worth running |
| Engagement: Agents | The testing agents installed inside the client's network with the owner's permission: add one, see what it may do and what it did, remove it |
| Engagement: Run tests | Start a test, see earlier tests, read results |
| Engagement: Findings | The weaknesses found; one opens with fix steps, proof, status and re-check |
| Engagement: Risk picture | How findings combine into routes an attacker could take |
| Findings | Every finding across the workspace, by status and severity |
| Defenses | What the defenders did for each attacker technique, and breach readiness |
| Forensics | Add evidence with a provable chain of custody, check files, read logs into an attack timeline, match known threats |
| Reports | Download the shareable report |
| Activity log | The tamper-evident record, with a filter and a download |
| About | What Ares is, and the copyright and rights notice |

Shared data lives in `src/features/workspace/data.ts`: the hooks for
engagements, tests (`ListJobs`), findings (`ListFindings`, `SetFindingStatus`)
and defender coverage. `src/lib/local.ts` holds only what the browser itself
remembers: tests still running, and past report downloads.

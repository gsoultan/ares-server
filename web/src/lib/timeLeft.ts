import type { JobProgress } from "../gen/ares/v1/ares_pb.ts";

// How long a running test has left, in words. The server gives a range, or no
// number at all until it has something to go on; this never turns that into a
// falsely precise countdown.

export interface TimeLeft {
  // Short, for a badge: "About 3 min left".
  short: string;
  // When it should be done by, as a clock time, if there is an estimate.
  by?: string;
  // The step count, when the check reports one and its total is settled.
  fraction?: number;
}

function minutes(s: number): number {
  return Math.max(1, Math.round(s / 60));
}

function span(low: number, high: number): string {
  if (high <= 20) return "Almost done";
  if (high < 60) return "Under a minute left";
  if (high >= 90 * 60) {
    const lo = Math.max(1, Math.round(low / 3600));
    const hi = Math.max(lo, Math.round(high / 3600));
    return lo === hi ? `About ${hi} h left` : `About ${lo}–${hi} h left`;
  }
  const hi = minutes(high);
  if (low < 60) return `Under ${hi} min left`;
  const lo = Math.min(hi, minutes(low));
  return lo === hi ? `About ${hi} min left` : `About ${lo}–${hi} min left`;
}

function clock(secondsFromNow: number): string {
  return new Date(Date.now() + secondsFromNow * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeLeft(p: JobProgress | undefined): TimeLeft | undefined {
  if (!p || p.state === "" || p.state === "done") return undefined;
  const fraction = p.total > 0 && !p.totalMayGrow ? Math.min(1, p.done / p.total) : undefined;
  switch (p.state) {
    case "estimate": {
      const low = Number(p.remainingLowSeconds);
      const high = Number(p.remainingHighSeconds);
      return { short: span(low, high), by: high >= 60 ? clock(high) : undefined, fraction };
    }
    case "finishing":
      return { short: "Wrapping up…", fraction: 1 };
    case "overdue":
      return { short: "Taking longer than usual", fraction };
    default:
      return { short: "Estimating time left…", fraction };
  }
}

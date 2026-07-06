// Types mirror the Go structs in inspect/inspector.go.

export type Severity = "info" | "warn" | "danger";
export type Verdict = "ok" | "caution" | "suspicious";

export interface Hop {
  url: string;
  status: number;
  https: boolean;
}

export interface Finding {
  severity: Severity;
  code: string;
  message: string;
}

export interface InspectResult {
  input_url: string;
  final_url: string;
  redirect_chain: Hop[];
  findings: Finding[];
  verdict: Verdict;
}

// ApiError carries the server's human-readable message so the UI can show
// it verbatim ("host cannot be resolved", "the host did not respond in
// time", ...).
export class ApiError extends Error {}

export async function inspectURL(url: string): Promise<InspectResult> {
  let res: Response;
  try {
    res = await fetch("/api/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new ApiError("Could not reach the inspection service — is it running?");
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new ApiError(
      body?.error ?? `The inspection service answered with status ${res.status}`,
    );
  }
  return body as InspectResult;
}

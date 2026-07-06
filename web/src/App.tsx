import { useState, type FormEvent } from "react";
import { inspectURL, ApiError, type InspectResult } from "./api";
import VerdictBanner from "./VerdictBanner";
import RedirectChain from "./RedirectChain";
import Findings from "./Findings";

type State =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; result: InspectResult }
  | { status: "error"; message: string };

const EXAMPLES = [
  "https://www.admin.ch/aktuelles",
  "https://bit.ly/3vTFLhW",
  "http://paypal.com.account-check.example",
];

export default function App() {
  const [input, setInput] = useState("");
  const [state, setState] = useState<State>({ status: "idle" });

  async function inspect(raw: string) {
    const trimmed = raw.trim();
    if (trimmed === "" || state.status === "loading") return;
    // People paste links without a scheme; the API (rightly) insists on one.
    const url = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    setInput(trimmed);
    setState({ status: "loading" });
    try {
      setState({ status: "done", result: await inspectURL(url) });
    } catch (err) {
      setState({
        status: "error",
        message:
          err instanceof ApiError ? err.message : "Bei der Prüfung ist etwas schiefgelaufen",
      });
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    void inspect(input);
  }

  return (
    <div className="page">
      <header className="masthead">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">L</div>
          <span className="brand-name">LinkCheck</span>
        </div>
        <h1>
          Wohin führt dieser Link
          <br />
          <span className="accent">wirklich?</span>
        </h1>
        <p className="tagline">
          Wir folgen jeder Weiterleitung serverseitig und zeigen Ihnen das echte Ziel —
          samt typischer Phishing-Muster. Bevor Sie klicken.
        </p>
      </header>

      <form className="inspect-form" onSubmit={onSubmit}>
        <label className="visually-hidden" htmlFor="url">
          Zu prüfender Link
        </label>
        <input
          id="url"
          type="text"
          inputMode="url"
          autoFocus
          spellCheck={false}
          placeholder="Link einfügen, z. B. https://bit.ly/…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button type="submit" disabled={state.status === "loading" || input.trim() === ""}>
          {state.status === "loading" ? "Prüfe…" : "Prüfen"}
        </button>
      </form>

      {state.status === "idle" && (
        <p className="examples">
          Beispiele:{" "}
          {EXAMPLES.map((ex) => (
            <button key={ex} type="button" className="example-chip" onClick={() => void inspect(ex)}>
              {ex}
            </button>
          ))}
        </p>
      )}

      <main aria-live="polite">
        {state.status === "loading" && (
          <div className="scanning" role="status">
            <div className="scanning-bar" />
            <p>Wir folgen der Weiterleitungsspur…</p>
          </div>
        )}

        {state.status === "error" && (
          <div className="error-card" role="alert">
            <h2>Dieser Link konnte nicht geprüft werden</h2>
            <p>{state.message}</p>
          </div>
        )}

        {state.status === "done" && (
          <article className="report">
            <VerdictBanner verdict={state.result.verdict} />
            <RedirectChain chain={state.result.redirect_chain} finalURL={state.result.final_url} />
            <Findings findings={state.result.findings} />
          </article>
        )}
      </main>

      <footer className="colophon">
        <p>
          Prüfungen laufen serverseitig; nichts wird gespeichert. Weiterleitungen werden
          mit strikten Sicherheitslimits verfolgt — interne Adressen werden nie kontaktiert.
        </p>
      </footer>
    </div>
  );
}

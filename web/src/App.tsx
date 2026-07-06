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
          err instanceof ApiError ? err.message : "Something went wrong while inspecting",
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
        <h1>
          Link<span className="masthead-dash">—</span>Inspector
        </h1>
        <p className="tagline">See where a link really leads before you click it.</p>
      </header>

      <form className="inspect-form" onSubmit={onSubmit}>
        <label className="visually-hidden" htmlFor="url">
          Link to inspect
        </label>
        <input
          id="url"
          type="text"
          inputMode="url"
          autoFocus
          spellCheck={false}
          placeholder="Paste a link, e.g. https://bit.ly/…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button type="submit" disabled={state.status === "loading" || input.trim() === ""}>
          {state.status === "loading" ? "Inspecting…" : "Inspect"}
        </button>
      </form>

      {state.status === "idle" && (
        <p className="examples">
          Try:{" "}
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
            <p>Following the redirect trail…</p>
          </div>
        )}

        {state.status === "error" && (
          <div className="error-card" role="alert">
            <h2>Could not inspect that link</h2>
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
          Checks run server-side; nothing is stored. Redirects are followed with strict
          safety limits — internal addresses are never contacted.
        </p>
      </footer>
    </div>
  );
}

import type { Hop } from "./api";

function statusClass(status: number): string {
  if (status >= 200 && status < 300) return "status-2xx";
  if (status >= 300 && status < 400) return "status-3xx";
  return "status-err";
}

export default function RedirectChain({ chain, finalURL }: { chain: Hop[]; finalURL: string }) {
  if (chain.length === 0) {
    return (
      <section className="chain">
        <h2>Weiterleitungsspur</h2>
        <p className="chain-empty">
          Dem Link wurde nicht gefolgt — die Befunde unten erklären, warum.
        </p>
      </section>
    );
  }
  return (
    <section className="chain">
      <h2>
        Weiterleitungsspur
        <span className="chain-count">
          {chain.length === 1 ? "keine Weiterleitungen" : `${chain.length} Stationen`}
        </span>
      </h2>
      <ol>
        {chain.map((hop, i) => (
          <li key={`${i}-${hop.url}`} className="hop" style={{ animationDelay: `${i * 90}ms` }}>
            <span className={`hop-status ${statusClass(hop.status)}`}>{hop.status}</span>
            <span
              className={hop.https ? "hop-lock" : "hop-lock hop-lock-off"}
              title={hop.https ? "Verschlüsselt (https)" : "Unverschlüsselt (http)"}
            >
              {hop.https ? "https" : "http"}
            </span>
            <span className="hop-url">{hop.url}</span>
          </li>
        ))}
      </ol>
      {finalURL && (
        <p className="chain-final">
          Endet bei <strong className="hop-url">{finalURL}</strong>
        </p>
      )}
    </section>
  );
}

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
        <h2>Redirect trail</h2>
        <p className="chain-empty">
          The link was not followed — see the findings below for why.
        </p>
      </section>
    );
  }
  return (
    <section className="chain">
      <h2>
        Redirect trail
        <span className="chain-count">
          {chain.length === 1 ? "no redirects" : `${chain.length} stops`}
        </span>
      </h2>
      <ol>
        {chain.map((hop, i) => (
          <li key={`${i}-${hop.url}`} className="hop" style={{ animationDelay: `${i * 90}ms` }}>
            <span className={`hop-status ${statusClass(hop.status)}`}>{hop.status}</span>
            <span
              className={hop.https ? "hop-lock hop-lock-on" : "hop-lock hop-lock-off"}
              title={hop.https ? "Encrypted (https)" : "Not encrypted (http)"}
            >
              {hop.https ? "🔒" : "⚠"}
            </span>
            <span className="hop-url">{hop.url}</span>
          </li>
        ))}
      </ol>
      {finalURL && (
        <p className="chain-final">
          Ends at <strong className="hop-url">{finalURL}</strong>
        </p>
      )}
    </section>
  );
}

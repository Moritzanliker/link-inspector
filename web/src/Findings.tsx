import type { Finding, Severity } from "./api";

const GROUPS: { severity: Severity; title: string }[] = [
  { severity: "danger", title: "Danger signs" },
  { severity: "warn", title: "Worth checking" },
  { severity: "info", title: "Notes" },
];

export default function Findings({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <section className="findings">
        <h2>Findings</h2>
        <p className="findings-none">Nothing suspicious detected by any check.</p>
      </section>
    );
  }
  return (
    <section className="findings">
      <h2>Findings</h2>
      {GROUPS.map(({ severity, title }) => {
        const group = findings.filter((f) => f.severity === severity);
        if (group.length === 0) return null;
        return (
          <div key={severity} className={`finding-group finding-group-${severity}`}>
            <h3>{title}</h3>
            <ul>
              {group.map((f, i) => (
                <li key={`${f.code}-${i}`} className="finding">
                  <span className="finding-code">{f.code.replaceAll("_", " ")}</span>
                  <p>{f.message}</p>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </section>
  );
}

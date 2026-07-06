import type { Verdict } from "./api";

const COPY: Record<Verdict, { label: string; detail: string }> = {
  ok: {
    label: "Looks OK",
    detail: "No obvious tricks found. Still, only continue if you expected this link.",
  },
  caution: {
    label: "Caution",
    detail: "Some things about this link deserve a second look before you continue.",
  },
  suspicious: {
    label: "Suspicious",
    detail: "This link shows patterns typical of phishing. Do not enter any data there.",
  },
};

export default function VerdictBanner({ verdict }: { verdict: Verdict }) {
  return (
    <section className={`verdict verdict-${verdict}`}>
      <span className="verdict-stamp">{COPY[verdict].label}</span>
      <p>{COPY[verdict].detail}</p>
    </section>
  );
}

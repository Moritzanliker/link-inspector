import type { Verdict } from "./api";

const COPY: Record<Verdict, { label: string; detail: string }> = {
  ok: {
    label: "Sieht ok aus",
    detail:
      "Keine offensichtlichen Tricks gefunden. Fahren Sie trotzdem nur fort, wenn Sie diesen Link erwartet haben.",
  },
  caution: {
    label: "Vorsicht",
    detail: "Einige Merkmale dieses Links verdienen einen zweiten Blick, bevor Sie fortfahren.",
  },
  suspicious: {
    label: "Verdächtig",
    detail: "Dieser Link zeigt typische Phishing-Muster. Geben Sie dort keine Daten ein.",
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

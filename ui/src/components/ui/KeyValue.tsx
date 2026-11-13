import type { ReactNode } from "react";

export interface KeyValueEntry {
  label: string;
  value: ReactNode;
  mono?: boolean;
}

export function KeyValueGrid({ entries }: { entries: KeyValueEntry[] }) {
  return (
    <dl className="kv-grid">
      {entries.map((entry) => (
        <div className="kv" key={entry.label}>
          <dt>{entry.label}</dt>
          <dd className={entry.mono ? "mono" : undefined}>{entry.value}</dd>
        </div>
      ))}
    </dl>
  );
}

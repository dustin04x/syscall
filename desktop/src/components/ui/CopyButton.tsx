import { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopyButton({ value, label = "Copy value" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button
      type="button"
      className="copy-btn"
      onClick={(event) => {
        event.stopPropagation();
        void copy();
      }}
      aria-label={label}
      title={copied ? "Copied" : label}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

export function Copyable({
  value,
  display,
  label
}: {
  value: string;
  display?: string;
  label?: string;
}) {
  return (
    <span className="copyable">
      <code className="mono">{display ?? value}</code>
      <CopyButton value={value} label={label} />
    </span>
  );
}

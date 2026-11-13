import type { ReactNode } from "react";
import { AlertTriangle, FileSearch, RefreshCw } from "lucide-react";

import { Button } from "./Button";

export function LoadingState({
  label = "Loading evidence",
  compact = false
}: {
  label?: string;
  compact?: boolean;
}) {
  return (
    <div
      className={`state-block ${compact ? "compact" : ""}`.trim()}
      role="status"
      aria-live="polite"
    >
      <div className="state-title">{label}</div>
      <div className="loading-rail" aria-hidden="true" />
    </div>
  );
}

export function ErrorState({
  title = "Unable to load evidence",
  message,
  code,
  onRetry,
  compact = false
}: {
  title?: string;
  message: string;
  code?: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  return (
    <div
      className={`state-block ${compact ? "compact" : ""}`.trim()}
      role="alert"
    >
      <div className="state-glyph" aria-hidden="true">
        <AlertTriangle size={13} />
      </div>
      <div className="state-title">{title}</div>
      <p className="state-body">{message}</p>
      {code ? <span className="state-code">{code}</span> : null}
      {onRetry ? (
        <div className="state-actions">
          <Button size="sm" onClick={onRetry}>
            <RefreshCw size={11} /> Retry
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export function EmptyState({
  title,
  message,
  icon,
  action,
  compact = false
}: {
  title: string;
  message: string;
  icon?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={`state-block ${compact ? "compact" : ""}`.trim()}>
      <div className="state-glyph" aria-hidden="true">
        {icon ?? <FileSearch size={13} />}
      </div>
      <div className="state-title">{title}</div>
      <p className="state-body">{message}</p>
      {action ? <div className="state-actions">{action}</div> : null}
    </div>
  );
}

export function Notice({
  tone = "info",
  title,
  children
}: {
  tone?: "info" | "warning" | "critical";
  title?: string;
  children: ReactNode;
}) {
  return (
    <div className={`notice notice-${tone}`} role={tone === "critical" ? "alert" : "status"}>
      <AlertTriangle size={13} aria-hidden="true" />
      <div>
        {title ? <div className="notice-title">{title}</div> : null}
        <div className="notice-body">{children}</div>
      </div>
    </div>
  );
}

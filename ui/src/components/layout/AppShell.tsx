import type { ReactNode } from "react";
import { Database, FolderSearch, LayoutDashboard, LockKeyhole } from "lucide-react";

import type { AppInfo } from "../../types/contracts";
import type { Route } from "../../lib/routes";
import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import { formatNumber } from "../../lib/format";
import { StatusBadge } from "../ui/Badges";
import { useIndicator } from "../../hooks/useIndicator";

const primaryItems = [
  { path: "/overview", label: "Overview", icon: LayoutDashboard },
  { path: "/sessions", label: "Sessions", icon: FolderSearch }
];

export function AppShell({
  info,
  route,
  navigate,
  boot = false,
  children
}: {
  info: AppInfo | null;
  route: Route;
  navigate: (path: string) => void;
  boot?: boolean;
  children: ReactNode;
}) {
  const section = route.kind === "overview" ? "overview" : "sessions";
  const routeLabel =
    route.kind === "overview" ? "Overview" : route.kind === "sessions" ? "Sessions" : "Investigation";
  const contract = info?.contractVersion.replace("syscall-desktop/", "");
  const sessionId = route.kind === "investigation" ? route.sessionId : null;
  const detail = useAsync(
    () => (sessionId ? api.getSession(sessionId) : Promise.resolve(null)),
    [sessionId]
  );

  const { containerRef: navRef, box: navBox } = useIndicator<HTMLElement>(section);

  return (
    <div className={`app-shell${boot ? " boot" : ""}`}>
      <aside className="spine">
        <button
          type="button"
          className="brand"
          onClick={() => navigate("/overview")}
          aria-label="SYSCALL — back to overview"
        >
          <span className="brand-word">
            <span className="brand-name">SYSCALL</span>
            <span className="brand-tick" aria-hidden="true" />
          </span>
          <span className="brand-line">every process has a story</span>
        </button>

        <nav className="spine-nav" aria-label="Primary" ref={navRef}>
          <div className="spine-nav-label">workspace</div>
          {navBox ? (
            <span
              className="nav-glider"
              aria-hidden="true"
              style={{ transform: `translateY(${navBox.y}px)`, height: navBox.h }}
            />
          ) : null}
          {primaryItems.map((item) => (
            <button
              key={item.path}
              type="button"
              className="nav-link"
              data-active={section === (item.path === "/overview" ? "overview" : "sessions") ? "true" : "false"}
              aria-current={section === (item.path === "/overview" ? "overview" : "sessions") ? "page" : undefined}
              onClick={() => navigate(item.path)}
            >
              <span className="nav-index" aria-hidden="true">
                {item.path === "/overview" ? "01" : "02"}
              </span>
              <item.icon size={14} aria-hidden="true" />
              <span className="nav-text">{item.label}</span>
            </button>
          ))}
        </nav>

        {sessionId ? (
          <div className="spine-context">
            <div className="spine-context-label">open investigation</div>
            {detail.data ? (
              <>
                <StatusBadge status={detail.data.session.status} />
                <div className="spine-context-meta">
                  {formatNumber(detail.data.stats.eventCount)} events ·{" "}
                  {formatNumber(detail.data.stats.processCount)} processes
                </div>
              </>
            ) : null}
          </div>
        ) : (
          <div className="spine-context" aria-hidden="true" />
        )}

        <div className="spine-foot">
          <div
            className="spine-state"
            title={info?.databaseExists ? "Evidence store online" : "Evidence store unavailable"}
          >
            <Database size={10} aria-hidden="true" />
            <span>{info?.databaseExists ? "store" : "no db"}</span>
            <span
              className={`runtime-dot ${info?.databaseExists ? "" : "offline"}`.trim()}
              aria-hidden="true"
            />
          </div>
          <div className="spine-state" title={info?.readOnly ? "Read-only workbench" : "Write access"}>
            <LockKeyhole size={10} aria-hidden="true" />
            <span>{info?.readOnly ? "read only" : "writable"}</span>
          </div>
          <div className="spine-path" title={info?.databasePath}>
            {info?.databasePath ?? "resolving database"}
          </div>
        </div>
      </aside>

      <main className="main-column">
        <div className="shell-strip">
          <div className="strip-left">
            <span className="strip-mark">S/</span>
            <span>workbench</span>
            <span className="strip-slash">/</span>
            <span className="strip-current">{routeLabel}</span>
            {route.kind === "investigation" ? (
              <span className="strip-session">{route.sessionId}</span>
            ) : null}
          </div>
          <div className="strip-right">
            <span className="strip-status">
              <span
                className={`runtime-dot ${info?.databaseExists ? "" : "offline"}`.trim()}
                aria-hidden="true"
              />
              {info?.databaseExists ? "store connected" : "store missing"}
            </span>
            <span className="strip-divider" aria-hidden="true" />
            <span>read only</span>
            <span className="strip-divider" aria-hidden="true" />
            <span className="mono">contract {contract ?? "…"}</span>
          </div>
        </div>
        <div className="shell-content">
          <div className="shell-inner">{children}</div>
        </div>
      </main>
    </div>
  );
}

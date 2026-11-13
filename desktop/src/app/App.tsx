import { useEffect, useState } from "react";

import { useAsync } from "../hooks/useAsync";
import { useRoute } from "../hooks/useRoute";
import { api } from "../lib/api";
import { AppShell } from "../components/layout/AppShell";
import { ErrorState, LoadingState } from "../components/ui/States";
import { Button } from "../components/ui/Button";
import { OverviewPage } from "../features/overview/OverviewPage";
import { SessionsPage } from "../features/sessions/SessionsPage";
import { InvestigationPage } from "../features/investigation/InvestigationPage";

export function App() {
  const { route, navigate } = useRoute();
  const info = useAsync(() => api.appInfo(), []);
  const [ready, setReady] = useState(false);
  // The boot choreography must yield to route transitions once it has played.
  const [boot, setBoot] = useState(true);

  useEffect(() => {
    if (info.data && !ready) setReady(true);
  }, [info.data, ready]);

  useEffect(() => {
    const timer = window.setTimeout(() => setBoot(false), 900);
    return () => window.clearTimeout(timer);
  }, []);

  if (info.loading && !info.data) {
    return (
      <div className="app-shell" style={{ gridTemplateColumns: "1fr" }}>
        <main className="main-column" style={{ justifyContent: "center" }}>
          <div className="page" style={{ margin: "0 auto" }}>
            <LoadingState label="Opening the evidence store" />
          </div>
        </main>
      </div>
    );
  }

  if (info.error || !info.data) {
    return (
      <div className="app-shell" style={{ gridTemplateColumns: "1fr" }}>
        <main className="main-column" style={{ justifyContent: "center" }}>
          <div className="page" style={{ margin: "0 auto", maxWidth: 560 }}>
            <div className="panel">
              <ErrorState
                title="Desktop backend unavailable"
                message={
                  info.error ??
                  "The Tauri backend did not return application information. Launch the desktop binary rather than the browser development server."
                }
                code="BACKEND_UNAVAILABLE"
                onRetry={info.reload}
              />
            </div>
            <div style={{ textAlign: "center", marginTop: 12 }}>
              <Button variant="ghost" onClick={() => info.reload()}>
                Retry backend handshake
              </Button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  // Re-key per context change only: tab and deep-link ids swap the body,
  // they do not replay the whole page entrance.
  const routeKey =
    route.kind === "investigation" ? `investigation:${route.sessionId}` : route.kind;

  return (
    <AppShell info={info.data} route={route} navigate={navigate} boot={boot}>
      <div key={routeKey} className="page-enter">
        {route.kind === "overview" ? <OverviewPage navigate={navigate} /> : null}
        {route.kind === "sessions" ? <SessionsPage navigate={navigate} /> : null}
        {route.kind === "investigation" ? (
          <InvestigationPage
            sessionId={route.sessionId}
            tab={route.tab}
            eventId={route.eventId}
            processInstanceId={route.processInstanceId}
            navigate={navigate}
          />
        ) : null}
      </div>
    </AppShell>
  );
}

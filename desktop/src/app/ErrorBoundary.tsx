import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertOctagon } from "lucide-react";

import { Button } from "../components/ui/Button";

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Workbench render failure", error, info.componentStack);
  }

  override render() {
    if (this.state.error) {
      return (
        <div className="page">
          <div className="panel">
            <div className="state-block" role="alert">
              <div className="state-glyph" aria-hidden="true">
                <AlertOctagon size={13} />
              </div>
              <div className="state-title">The workbench encountered a rendering failure</div>
              <p className="state-body">
                No evidence was modified. Reload the interface to restore the session browser.
              </p>
              <div className="state-actions">
                <Button onClick={() => window.location.reload()}>Reload workbench</Button>
              </div>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

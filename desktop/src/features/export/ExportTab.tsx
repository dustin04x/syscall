import { useState, type CSSProperties } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileArchive,
  Lock,
  PackageCheck
} from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import { formatBytes } from "../../lib/format";
import type { ExportResult, SessionDetail } from "../../types/contracts";
import { Tag } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { Copyable } from "../../components/ui/CopyButton";
import { ErrorState, Notice } from "../../components/ui/States";

export function ExportTab({ detail }: { detail: SessionDetail }) {
  const info = useAsync(() => api.appInfo(), []);
  const [exporting, setExporting] = useState(false);
  const [result, setResult] = useState<ExportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [overwriteNeeded, setOverwriteNeeded] = useState(false);

  const session = detail.session;
  const expectedPath = info.data
    ? `${info.data.exportDirectory}/${session.id}.json`
    : `${session.id}.json`;

  async function runExport(force: boolean) {
    setExporting(true);
    setError(null);
    try {
      const output = await api.exportSession(session.id, force);
      setResult(output);
      setOverwriteNeeded(false);
    } catch (reason) {
      const message =
        typeof reason === "object" && reason !== null && "message" in reason
          ? String((reason as { message: unknown }).message)
          : "Export failed.";
      setError(message);
      setOverwriteNeeded(/already exists|confirm overwrite|--force/i.test(message));
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="ex-layout stagger" style={{ "--i": 0 } as CSSProperties}>
      <div className="ex-main">
        {session.evidenceIncomplete ? (
          <div style={{ marginBottom: 16 }}>
            <Notice tone="warning" title="Incomplete evidence will be exported as recorded">
              The package preserves declared loss counters and limitations. Export does not repair or
              fill missing events.
            </Notice>
          </div>
        ) : null}

        <div className="ex-op">
          <div className="ex-glyph" aria-hidden="true">
            <FileArchive size={15} />
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div className="row" style={{ gap: 10 }}>
              <span className="ex-op-title">Session evidence bundle</span>
              <Tag>.json</Tag>
            </div>
            <div className="ex-op-path">
              {info.loading ? "resolving destination" : info.data?.exportDirectory ?? "backend managed"} ·{" "}
              {session.id}.json
            </div>
          </div>
        </div>

        {info.error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorState compact message={info.error} onRetry={info.reload} />
          </div>
        ) : null}

        <div className="detail-section" style={{ marginTop: 14 }}>
          <div className="detail-section-label">included components</div>
          <div className="accounting-grid" style={{ gridTemplateColumns: "repeat(2, minmax(0,1fr))" }}>
            <div className="accounting-cell">
              <dt>Metadata</dt>
              <dd style={{ whiteSpace: "normal" }}>Export format, build, timestamp, database path, limitations.</dd>
            </div>
            <div className="accounting-cell">
              <dt>Session</dt>
              <dd style={{ whiteSpace: "normal" }}>Lifecycle, command, scope, counters, termination.</dd>
            </div>
            <div className="accounting-cell">
              <dt>Process instances</dt>
              <dd style={{ whiteSpace: "normal" }}>Derived identities and observed ancestry.</dd>
            </div>
            <div className="accounting-cell">
              <dt>Events</dt>
              <dd style={{ whiteSpace: "normal" }}>Persisted typed events with provenance.</dd>
            </div>
            <div className="accounting-cell">
              <dt>Analysis</dt>
              <dd style={{ whiteSpace: "normal" }}>Behavioral findings from the deterministic rule set.</dd>
            </div>
            <div className="accounting-cell">
              <dt>Verification + manifest</dt>
              <dd style={{ whiteSpace: "normal" }}>Integrity report; SHA-256 digest per component.</dd>
            </div>
          </div>
        </div>

        {overwriteNeeded ? (
          <div className="ex-confirm" style={{ marginTop: 16 }}>
            <AlertTriangle size={14} style={{ color: "var(--warning)", flex: "none", marginTop: 2 }} aria-hidden="true" />
            <div>
              <div className="ex-confirm-body-title">An export already exists</div>
              <div className="ex-confirm-body-note">
                Replacing it writes a new package atomically with mode 0600. The previous file cannot
                be recovered.
              </div>
              <div className="ex-confirm-actions">
                <Button variant="danger" size="sm" onClick={() => void runExport(true)}>
                  Replace existing export
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setOverwriteNeeded(false);
                    setError(null);
                  }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <div className="row" style={{ marginTop: 18, gap: 10 }}>
            <Button
              variant="primary"
              disabled={exporting || info.loading || Boolean(info.error)}
              onClick={() => void runExport(false)}
            >
              <Download size={12} aria-hidden="true" />
              {exporting ? "Exporting evidence" : "Export evidence"}
            </Button>
            {exporting ? <span className="micro">building package</span> : null}
          </div>
        )}
        {exporting ? <div className="ex-progress" aria-hidden="true" /> : null}

        {error && !overwriteNeeded ? (
          <div style={{ marginTop: 14 }}>
            <Notice tone="critical" title="Export failed">
              {error}
            </Notice>
          </div>
        ) : null}

        {result ? (
          <section style={{ marginTop: 22 }} aria-label="Export result">
            <div className="ex-result-head">
              <CheckCircle2 size={14} style={{ color: "var(--ok)" }} aria-hidden="true" />
              <span className="ex-result-title">Package written successfully</span>
              <Tag tone="ok">exported</Tag>
            </div>
            <div className="mono faint" style={{ fontSize: 10, marginTop: 6 }}>
              {formatBytes(result.bytesWritten)} · {result.formatVersion} · mode 0600
            </div>
            <div className="code-block" style={{ marginTop: 8 }}>
              {result.outputPath}
            </div>
            <div className="row" style={{ marginTop: 8 }}>
              <Copyable value={result.outputPath} label="Copy export path" />
            </div>

            <div className="table-scroll" style={{ marginTop: 14, border: "1px solid var(--line)" }}>
              <table className="data-table" aria-label="Export manifest">
                <thead>
                  <tr>
                    <th scope="col">Component</th>
                    <th scope="col">Format</th>
                    <th scope="col">Version</th>
                    <th scope="col" style={{ textAlign: "right" }}>
                      Bytes
                    </th>
                    <th scope="col">SHA-256</th>
                  </tr>
                </thead>
                <tbody>
                  {result.manifest.map((entry) => (
                    <tr key={entry.component}>
                      <td className="mono" style={{ color: "var(--text)" }}>
                        {entry.component}
                      </td>
                      <td className="mono faint">{entry.format}</td>
                      <td className="mono faint">{entry.version}</td>
                      <td className="cell-num">{entry.byteLength}</td>
                      <td style={{ maxWidth: 220 }}>
                        <Copyable
                          value={entry.sha256}
                          display={`${entry.sha256.slice(0, 16)}…${entry.sha256.slice(-8)}`}
                          label={`Copy ${entry.component} SHA-256`}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="table-foot" style={{ borderInline: "1px solid var(--line)" }}>
              <span>the manifest verifies post-export package integrity</span>
              <span>no provenance claim is made about the original database</span>
            </div>
          </section>
        ) : (
          <section style={{ marginTop: 22 }} aria-label="Export result placeholder">
            <div className="state-block">
              <div className="state-glyph" aria-hidden="true">
                <PackageCheck size={13} />
              </div>
              <div className="state-title">No package created in this view</div>
              <p className="state-body">
                Export writes only to the backend-managed destination. Existing files require an
                explicit replacement confirmation.
              </p>
            </div>
          </section>
        )}
      </div>

      <aside className="ex-side" aria-label="Export policy">
        <div className="ex-side-block">
          <div className="section-label" style={{ marginBottom: 10 }}>
            destination policy
          </div>
          <div className="integrity-lines">
            <div className="integrity-line">
              <span className="integrity-label">Controlled by</span>
              <span className="integrity-value">backend config</span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Expected path</span>
              <span className="integrity-value mono" style={{ fontSize: 9, maxWidth: 150 }}>
                {expectedPath}
              </span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Permissions</span>
              <span className="integrity-value">0700 · 0600</span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Overwrite</span>
              <span className="integrity-value">refused unless confirmed</span>
            </div>
          </div>
          <p className="verify-note" style={{ marginTop: 10 }}>
            The interface cannot choose an arbitrary filesystem path, so evidence cannot be silently
            written elsewhere through export.
          </p>
        </div>
        <div className="ex-side-block">
          <div className="section-label" style={{ marginBottom: 10 }}>
            <Lock size={10} aria-hidden="true" /> integrity semantics
          </div>
          <ul className="dotted-list">
            <li>SHA-256 covers canonical JSON bytes of each component.</li>
            <li>Verification runs read-only and never modifies recorded evidence.</li>
            <li>No digital signature or chain-of-custody guarantee is claimed.</li>
            <li>Known limitations are included rather than omitted.</li>
          </ul>
        </div>
        <div className="ex-side-block">
          <div className="section-label" style={{ marginBottom: 10 }}>
            before sharing
          </div>
          <ul className="dotted-list">
            <li>Review command arguments and file paths for sensitive values.</li>
            <li>Check evidence-loss counters and unresolved identities.</li>
            <li>Include the known limitations when handing off the package.</li>
            <li>Transfer through an approved channel; the package is not encrypted.</li>
          </ul>
        </div>
      </aside>
    </div>
  );
}

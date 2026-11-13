import type { ReactNode } from "react";

/* Panel — a bordered region of the grid with an optional caption row. */
export function Panel({
  title,
  actions,
  children,
  flush = false,
  className = "",
  footer,
  note
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
  footer?: ReactNode;
  note?: ReactNode;
}) {
  return (
    <section className={`panel ${className}`.trim()}>
      {title ? (
        <header className="panel-head">
          <h2 className="panel-title">{title}</h2>
          {actions}
        </header>
      ) : null}
      <div className={flush ? "panel-body-flush" : "panel-body"}>{children}</div>
      {footer ? <footer className="table-foot">{footer}</footer> : null}
      {note ? <div className="panel-note">{note}</div> : null}
    </section>
  );
}

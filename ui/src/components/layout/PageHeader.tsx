import type { ReactNode } from "react";

export function PageHeader({
  index,
  title,
  subtitle,
  actions
}: {
  index: string;
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div>
        <div className="page-head-index">
          <span className="idx">{index}</span>
          <span className="sep">/</span>
          <span>SYSCALL workbench</span>
        </div>
        <h1 className="page-title">{title}</h1>
        {subtitle ? <p className="page-sub">{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-aside">{actions}</div> : null}
    </header>
  );
}

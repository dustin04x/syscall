# SYSCALL Workbench — standalone UI

This folder is a **copy of the workbench renderer** packaged so it can be taken
away, edited without Rust or Tauri, and returned for re-wiring.

It is a normal Vite + React + TypeScript app. The production desktop application
in `../desktop/` is unchanged and still runs against the real SQLite evidence
through Tauri IPC.

## Run it

```bash
cd ui
npm install
npm run dev
```

Open `http://127.0.0.1:1422`. The strict production check is:

```bash
npm run build
```

## What is preview data

The UI is driven by `src/mock/data.ts` through `src/lib/api.ts`. The data is
deterministic and fictional, marked `CONTRACT UI-PREVIEW` in the shell strip. It
is **not** evidence and must not be used to make forensic claims.

It contains two sessions:

- `mock-normal-001` — completed shell session, 43 events, 3 processes
- `mock-interrupt-002` — interrupted sleep session, 32 events, 1 process

All screens, filters, session navigation, process selection, event detail,
analysis, verification, and the simulated export flow work without a backend.

## Where to edit

- `src/styles/tokens.css`, `base.css`, `components.css`, `screens.css`,
  `motion.css` — the visual system, loaded in that order
- `src/components/` — shell, panels, badges, tables, fields, states
- `src/features/` — each workbench screen
- `src/lib/routes.ts` — hash routes
- `src/types/contracts.ts` — DTOs copied verbatim from the Rust contract

You can change markup, CSS, routes, components, and local UI state freely. Keep
`src/types/contracts.ts` aligned with the backend if you need new fields; new
fields require a corresponding Rust DTO change when this is returned.

## The one integration boundary

`src/lib/api.ts` is the only file that talks to data. In this preview it returns
mock data. The production version at `../desktop/src/lib/api.ts` calls:

```ts
invoke(command, { request })
```

against the existing Tauri 2 commands (`get_overview`, `list_sessions`,
`get_session`, `list_processes`, `query_timeline`, `query_filesystem`,
`query_network`, `get_event`, `run_analysis`, `run_verification`,
`export_session`, `app_info`).

When you return this folder, the wiring work is:

1. bring `ui/src` back into `desktop/src`;
2. replace the preview adapter with the Tauri adapter;
3. keep `src/types/contracts.ts` as the command contract;
4. rebuild and re-run the desktop checks.

No Rust rewrite should be needed unless the returned UI requires new data.

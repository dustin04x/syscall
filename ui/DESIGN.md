# SYSCALL interface design

## Direction

SYSCALL is a forensic reference workbench, not a monitoring dashboard. The interface uses a restrained "Center-Rail Reference" system: warm paper surfaces, ink-colored text, fine rules, and a vermilion accent for active navigation and evidence cues. Dense data stays calm and legible; semantic colors are reserved for status, severity, and uncertainty.

## Foundations

- **Color:** `src/styles/tokens.css` is the source of truth for paper, ink, accent, status, and event-type colors. Keep text and rules high-contrast on the light surfaces.
- **Typography:** Inter Variable for interface copy, Space Grotesk Variable for display and labels, and JetBrains Mono Variable for commands, identifiers, and measurements.
- **Shape and spacing:** Square corners, fine borders, and a 4px spacing rhythm keep the workbench precise without card-heavy decoration.
- **Interaction:** Preserve visible keyboard focus, clear hover/selected states, readable disabled states, and existing read-only evidence workflows.

## Layout

- The left rail provides persistent workspace navigation and session context; it collapses to an icon rail at narrower widths.
- Page headers establish section and task context before the evidence surface.
- Panels and tables use shared hairline boundaries to group related evidence without adding visual weight.
- Session rows retain their full evidence columns on wide screens, use a compact column set on medium screens, and become labeled cards at narrow widths.
- Summary metrics and investigation facts reflow to avoid clipped columns and horizontal page scrolling.

## Evidence language

Use the established status and severity tokens consistently. Keep incomplete, unavailable, or unresolved evidence explicit; never style preview data as real forensic evidence. Preserve the relationships and navigation between sessions, processes, events, findings, verification, and export.

## Responsive review

Check overview, sessions, process, and timeline views at narrow phone, tablet, and desktop widths. Confirm that page content does not create horizontal overflow, evidence labels remain visible, and selection and navigation behavior remain intact.

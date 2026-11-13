# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Linux systems engineers, cybersecurity researchers, and digital forensics investigators who need to understand and reconstruct activity recorded on a Linux machine.

## Product Purpose

SYSCALL is a hands-on Linux runtime investigation and forensic analysis workbench. It helps investigators inspect recorded process, filesystem, and network activity, follow behavioral findings to their supporting evidence, assess collection completeness, verify evidence, and export a session for further analysis.

Success means investigators can quickly understand a session, reconstruct what happened, and move between related processes, events, and findings without losing context.

## Positioning

SYSCALL focuses on understanding recorded Linux runtime activity and the relationships between processes, events, findings, and collected evidence. It is an investigative workbench, not an executive dashboard or generic SOC monitoring console.

## Operating Context

The core workflow is to select a recording session, assess its completeness, explore process relationships, reconstruct activity in the timeline, inspect process-related filesystem and network events, examine behavioral findings and supporting evidence, verify session integrity, and export evidence for further analysis or reporting.

The process explorer and forensic timeline are the signature, interconnected views of an investigation.

## Capabilities and Constraints

- The interface displays session summaries, process relationships, timeline events, filesystem and network activity, behavioral findings, verification results, and export options.
- Preserve the read-only investigation workflow and existing route, filter, selection, and export behavior.
- Keep evidence relationships, completeness, and uncertainty explicit; do not make incomplete or unresolved evidence appear conclusive.
- The standalone UI preview uses deterministic fictional data. It must remain clearly distinguishable from real forensic evidence.
- The production desktop application reads the evidence store through the existing Tauri API contract. Do not require backend or contract changes for UI work.

## Brand Commitments

Keep the SYSCALL name. The workbench should feel professional, precise, trustworthy, and designed for hands-on investigation.

## Evidence on Hand

The codebase contains the workbench screens and a deterministic fictional preview dataset. The preview data supports UI development and is not forensic evidence.

## Product Principles

- Put investigative tasks ahead of dashboard-style summaries.
- Make relationships between processes, events, findings, and evidence easy to follow.
- Preserve context while navigating large amounts of technical evidence.
- Distinguish confirmed, incomplete, and unresolved information.
- Keep the preview's fictional data separate from real forensic claims.

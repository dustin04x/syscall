import { useEffect, useMemo, useState, type CSSProperties } from "react";

import type { ProcessView } from "../../types/contracts";
import { truncateMiddle } from "../../lib/format";

/*
 * ProcessGraph — the observed ancestry drawn as a connected instrument.
 *
 * Layout is computed from observed parent-child links only: nodes without a
 * recorded parent become roots, and unresolved ancestry is shown as a dashed
 * stub rather than a fabricated link.
 */

const NODE_W = 180;
const NODE_H = 46;
const SLOT_W = 196;
const LEVEL_H = 84;
const PAD = 26;

interface Positioned {
  process: ProcessView;
  x: number;
  y: number;
  depth: number;
}

interface GraphLayout {
  nodes: Positioned[];
  edges: Array<{ id: string; from: Positioned; to: Positioned }>;
  width: number;
  height: number;
}

function visibleChildren(process: ProcessView, byId: Map<string, ProcessView>): ProcessView[] {
  return process.childInstanceIds
    .map((id) => byId.get(id))
    .filter((child): child is ProcessView => Boolean(child));
}

function computeLayout(
  processes: ProcessView[],
  byId: Map<string, ProcessView>,
  roots: string[],
  collapsed: Set<string>
): GraphLayout {
  const nodes: Positioned[] = [];
  const edges: Array<{ id: string; from: Positioned; to: Positioned }> = [];
  let cursor = 0;

  function place(id: string, depth: number, visited: Set<string>): Positioned | null {
    const process = byId.get(id);
    if (!process || visited.has(id)) return null;
    const nextVisited = new Set(visited).add(id);
    const children = visibleChildren(process, byId);
    const expanded = !collapsed.has(id);

    let x: number;
    const y = PAD + depth * LEVEL_H;
    const positioned: Positioned = { process, x: 0, y, depth };
    nodes.push(positioned);

    if (children.length > 0 && expanded) {
      const childNodes = children
        .map((child) => place(child.processInstanceId, depth + 1, nextVisited))
        .filter((child): child is Positioned => Boolean(child));
      if (childNodes.length > 0) {
        x = (childNodes[0]!.x + childNodes[childNodes.length - 1]!.x) / 2;
        childNodes.forEach((child) => {
          edges.push({ id: `${id}->${child.process.processInstanceId}`, from: positioned, to: child });
        });
      } else {
        x = cursor * SLOT_W + PAD + NODE_W / 2;
        cursor += 1;
      }
    } else {
      x = cursor * SLOT_W + PAD + NODE_W / 2;
      cursor += 1;
    }
    positioned.x = x;
    return positioned;
  }

  roots.forEach((rootId) => place(rootId, 0, new Set()));

  if (nodes.length === 0) {
    return { nodes, edges, width: PAD * 2 + NODE_W, height: PAD * 2 + NODE_H };
  }
  const maxDepth = Math.max(...nodes.map((node) => node.depth));
  return {
    nodes,
    edges,
    width: Math.max(cursor * SLOT_W + PAD * 2, PAD * 2 + NODE_W),
    height: PAD * 2 + (maxDepth + 1) * LEVEL_H + (LEVEL_H - NODE_H)
  };
}

function edgePath(from: Positioned, to: Positioned): string {
  const x1 = from.x;
  const y1 = from.y + NODE_H;
  const x2 = to.x;
  const y2 = to.y;
  const midY = y1 + (y2 - y1) / 2;
  return `M ${x1} ${y1} L ${x1} ${midY} L ${x2} ${midY} L ${x2} ${y2}`;
}

export function ProcessGraph({
  processes,
  roots,
  collapsed,
  selectedId,
  onSelect,
  onToggleCollapse
}: {
  processes: ProcessView[];
  roots: string[];
  collapsed: Set<string>;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onToggleCollapse: (id: string) => void;
}) {
  const byId = useMemo(() => new Map(processes.map((p) => [p.processInstanceId, p])), [processes]);
  const layout = useMemo(
    () => computeLayout(processes, byId, roots, collapsed),
    [processes, byId, roots, collapsed]
  );

  // Ancestor chain of the selection, for path highlighting.
  const selectedPath = useMemo(() => {
    if (!selectedId) return new Set<string>();
    const chain = new Set<string>([selectedId]);
    let current = byId.get(selectedId) ?? null;
    const guard = new Set<string>();
    while (current?.parentProcessInstanceId) {
      if (guard.has(current.processInstanceId)) break;
      guard.add(current.processInstanceId);
      const parent = byId.get(current.parentProcessInstanceId);
      if (!parent) break;
      chain.add(parent.processInstanceId);
      current = parent;
    }
    return chain;
  }, [selectedId, byId]);

  const inPathEdges = useMemo(() => {
    if (!selectedId) return new Set<string>();
    const set = new Set<string>();
    for (const edge of layout.edges) {
      const from = edge.from.process.processInstanceId;
      const to = edge.to.process.processInstanceId;
      if (selectedPath.has(from) && selectedPath.has(to)) set.add(edge.id);
    }
    return set;
  }, [layout.edges, selectedPath, selectedId]);

  const [drawKey, setDrawKey] = useState(0);
  const structureKey = `${layout.nodes.length}:${[...collapsed].sort().join(",")}`;
  useEffect(() => {
    setDrawKey((value) => value + 1);
  }, [structureKey]);

  return (
    <svg
      className="pg-svg"
      width={layout.width}
      height={layout.height}
      viewBox={`0 0 ${layout.width} ${layout.height}`}
      role="group"
      aria-label="Observed process ancestry graph"
    >
      {layout.edges.map((edge, index) => {
        const hot = inPathEdges.has(edge.id);
        return (
          <path
            key={`${edge.id}-${drawKey}`}
            d={edgePath(edge.from, edge.to)}
            className={`pg-edge draw ${hot ? "in-path" : ""}`.trim()}
            pathLength={1}
            style={{ "--d": index } as CSSProperties}
          />
        );
      })}

      {layout.nodes.map((node, index) => {
        const { process } = node;
        const isSelected = process.processInstanceId === selectedId;
        const inPath = selectedPath.has(process.processInstanceId);
        const children = visibleChildren(process, byId);
        const isCollapsed = collapsed.has(process.processInstanceId) && children.length > 0;
        return (
          <g
            key={process.processInstanceId}
            className={`pg-node ${isSelected ? "selected" : ""} ${inPath && !isSelected ? "in-path" : ""}`.trim()}
            transform={`translate(${node.x - NODE_W / 2} ${node.y})`}
            style={{ "--d": index } as CSSProperties}
          >
            <g className="pg-node-enter">
              {process.ancestryUnresolved ? (
                <>
                  <line
                    x1={NODE_W / 2}
                    y1={-16}
                    x2={NODE_W / 2}
                    y2={0}
                    stroke="var(--line-3)"
                    strokeDasharray="2 3"
                  />
                  <text className="pg-sub" x={NODE_W / 2 + 6} y={-6}>
                    ancestry ends here
                  </text>
                </>
              ) : null}
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={2}
                tabIndex={0}
                role="button"
                aria-pressed={isSelected}
                aria-label={`${process.comm}, pid ${process.pid}, ${process.eventCount} events. Activate to inspect.`}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(process.processInstanceId);
                  }
                }}
                onClick={() => onSelect(process.processInstanceId)}
              />
              <text
                x={10}
                y={18}
                style={{ pointerEvents: "none" }}
                onClick={() => onSelect(process.processInstanceId)}
              >
                {truncateMiddle(process.comm, 16)}
              </text>
              <text className="pg-sub" x={10} y={33} style={{ pointerEvents: "none" }}>
                pid {process.pid} · {process.eventCount} ev
              </text>
              {process.exitObserved ? (
                <rect x={NODE_W - 15} y={7} width={5} height={5} fill="var(--ok)" />
              ) : (
                <rect
                  x={NODE_W - 15}
                  y={7}
                  width={5}
                  height={5}
                  fill="none"
                  stroke="var(--text-faint)"
                />
              )}
              {process.identityUnresolved ? (
                <text className="pg-sub" x={NODE_W - 12} y={33} fill="var(--warning)">
                  ?
                </text>
              ) : null}
              {children.length > 0 ? (
                <g
                  role="button"
                  tabIndex={0}
                  aria-label={
                    isCollapsed
                      ? `Expand ${children.length} descendant${children.length === 1 ? "" : "s"} of ${process.comm}`
                      : `Collapse descendants of ${process.comm}`
                  }
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onToggleCollapse(process.processInstanceId);
                    }
                  }}
                  onClick={(event) => {
                    event.stopPropagation();
                    onToggleCollapse(process.processInstanceId);
                  }}
                  style={{ cursor: "pointer" }}
                >
                  <rect
                    className="pg-collapsed-rect"
                    x={NODE_W - 40}
                    y={NODE_H - 18}
                    width={30}
                    height={14}
                    rx={2}
                  />
                  <text
                    className="pg-badge"
                    x={NODE_W - 25}
                    y={NODE_H - 8}
                    textAnchor="middle"
                    style={{ pointerEvents: "none" }}
                  >
                    {isCollapsed ? `+${children.length}` : "−"}
                  </text>
                </g>
              ) : null}
            </g>
          </g>
        );
      })}
    </svg>
  );
}

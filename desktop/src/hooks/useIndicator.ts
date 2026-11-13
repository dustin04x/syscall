import { useCallback, useEffect, useRef, useState } from "react";

export interface IndicatorBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

/*
 * Measures the element inside `containerRef` marked data-active="true"
 * and returns its box, so a single indicator element can glide between
 * items with a transform transition. Container must be position:relative.
 */
export function useIndicator<T extends HTMLElement>(activeKey: unknown) {
  const containerRef = useRef<T | null>(null);
  const [box, setBox] = useState<IndicatorBox | null>(null);

  const measure = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const active = container.querySelector<HTMLElement>('[data-active="true"]');
    if (!active) {
      setBox(null);
      return;
    }
    setBox({
      x: active.offsetLeft,
      y: active.offsetTop,
      w: active.offsetWidth,
      h: active.offsetHeight
    });
  }, []);

  useEffect(() => {
    measure();
    // Font swap changes metrics; settle once when fonts are ready.
    let cancelled = false;
    document.fonts?.ready.then(() => {
      if (!cancelled) measure();
    }).catch(() => {});
    window.addEventListener("resize", measure);
    return () => {
      cancelled = true;
      window.removeEventListener("resize", measure);
    };
  }, [measure, activeKey]);

  return { containerRef, box };
}

import { useCallback, useEffect, useState } from "react";

import { parseRoute, type Route } from "../lib/routes";

export function useRoute(): { route: Route; navigate: (path: string) => void } {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));

  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const navigate = useCallback((path: string) => {
    const next = path.startsWith("#") ? path : `#${path.startsWith("/") ? path : `/${path}`}`;
    if (window.location.hash === next) {
      setRoute(parseRoute(next));
      return;
    }
    window.location.hash = next;
  }, []);

  return { route, navigate };
}

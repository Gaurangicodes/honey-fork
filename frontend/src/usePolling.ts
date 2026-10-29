import { useEffect, useRef, useState } from "react";

/**
 * Poll a fetcher until `stop` returns true (FR-UI-03: polling is sufficient).
 *
 * The interval is cleared on unmount and whenever `stop` flips, so a finished
 * scan stops issuing requests instead of polling forever.
 */
export function usePolling<T>(
  fetcher: () => Promise<T>,
  active: boolean,
  intervalMs = 1000,
): { data: T | null; error: string | null } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    let timer: number | undefined;

    const tick = async () => {
      try {
        const result = await fetcherRef.current();
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      }
      if (!cancelled) timer = window.setTimeout(tick, intervalMs);
    };

    void tick();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [active, intervalMs]);

  return { data, error };
}

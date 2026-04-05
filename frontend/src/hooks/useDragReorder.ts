import { useState, useCallback, useRef, type DragEvent } from "react";

/**
 * Generic drag-and-drop reorder hook.
 * Returns drag handlers and the reordered list.
 */
export function useDragReorder<T>(
  items: T[],
  onReorder: (reordered: T[]) => void,
) {
  const [dragIdx, setDragIdx] = useState<number | null>(null);
  const overIdx = useRef<number | null>(null);

  const onDragStart = useCallback(
    (idx: number) => (e: DragEvent) => {
      setDragIdx(idx);
      e.dataTransfer.effectAllowed = "move";
    },
    [],
  );

  const onDragOver = useCallback(
    (idx: number) => (e: DragEvent) => {
      e.preventDefault();
      overIdx.current = idx;
    },
    [],
  );

  const onDragEnd = useCallback(() => {
    if (dragIdx === null || overIdx.current === null || dragIdx === overIdx.current) {
      setDragIdx(null);
      overIdx.current = null;
      return;
    }
    const reordered = [...items];
    const [moved] = reordered.splice(dragIdx, 1);
    reordered.splice(overIdx.current, 0, moved!);
    setDragIdx(null);
    overIdx.current = null;
    onReorder(reordered);
  }, [dragIdx, items, onReorder]);

  return { dragIdx, onDragStart, onDragOver, onDragEnd };
}

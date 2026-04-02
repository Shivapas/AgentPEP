/** Placeholder page for routes not yet implemented. */

export function Placeholder({ title }: { title: string }) {
  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-foreground">{title}</h2>
      <p className="text-muted-foreground">
        This section will be implemented in a future sprint.
      </p>
    </div>
  );
}

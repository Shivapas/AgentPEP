export function Dashboard() {
  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Dashboard</h2>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatusCard title="Policy Rules" value="--" />
        <StatusCard title="Decisions Today" value="--" />
        <StatusCard title="Active Agents" value="--" />
      </div>
      <p className="text-muted-foreground">
        Policy Console is ready. Feature screens will be added in upcoming
        sprints.
      </p>
    </div>
  );
}

function StatusCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-6">
      <p className="text-sm text-muted-foreground">{title}</p>
      <p className="text-3xl font-bold text-card-foreground">{value}</p>
    </div>
  );
}

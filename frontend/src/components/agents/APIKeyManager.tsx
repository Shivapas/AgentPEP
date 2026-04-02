/**
 * APEP-123 — API Key Management UI
 * Generate, rotate, and revoke per-agent API keys.
 */
import { useEffect, useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import {
  listKeys,
  generateKey,
  rotateKey,
  revokeKey,
  type APIKey,
} from "@/api/agents";

export function APIKeyManager({ agentId }: { agentId: string }) {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [revealedKey, setRevealedKey] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await listKeys(agentId);
      setKeys(res.keys);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load keys");
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleGenerate() {
    setError(null);
    setRevealedKey(null);
    try {
      const key = await generateKey(agentId, newKeyName || "default");
      setRevealedKey(key.plain_key ?? null);
      setNewKeyName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate key");
    }
  }

  async function handleRotate(keyId: string) {
    if (!confirm("Rotate this key? The old key will be disabled.")) return;
    setError(null);
    try {
      const key = await rotateKey(agentId, keyId);
      setRevealedKey(key.plain_key ?? null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rotation failed");
    }
  }

  async function handleRevoke(keyId: string) {
    if (!confirm("Revoke this key? It will be permanently disabled.")) return;
    setError(null);
    try {
      await revokeKey(agentId, keyId);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Revoke failed");
    }
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">API Keys</h3>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {revealedKey && (
        <div className="rounded border border-green-500 bg-green-500/10 px-4 py-3 text-sm">
          <p className="mb-1 font-medium text-green-600">
            New key generated — copy it now, it won't be shown again:
          </p>
          <code className="block break-all rounded bg-muted px-2 py-1 text-xs">
            {revealedKey}
          </code>
        </div>
      )}

      {/* Generate form */}
      <div className="flex items-end gap-2">
        <div className="flex-1 space-y-1">
          <label className="text-sm font-medium">Key Name</label>
          <input
            type="text"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            placeholder="my-integration"
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
          />
        </div>
        <button
          onClick={handleGenerate}
          className="rounded bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
        >
          Generate Key
        </button>
      </div>

      {/* Key list */}
      {loading ? (
        <p className="text-sm text-muted-foreground">Loading keys...</p>
      ) : keys.length === 0 ? (
        <p className="text-sm text-muted-foreground">No API keys yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-muted/50">
              <tr>
                <th className="px-3 py-2 font-medium text-muted-foreground">Name</th>
                <th className="px-3 py-2 font-medium text-muted-foreground">Prefix</th>
                <th className="px-3 py-2 font-medium text-muted-foreground">Status</th>
                <th className="px-3 py-2 font-medium text-muted-foreground">Created</th>
                <th className="px-3 py-2 font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr
                  key={k.key_id}
                  className="border-b border-border last:border-0 hover:bg-muted/30"
                >
                  <td className="px-3 py-2">{k.name}</td>
                  <td className="px-3 py-2 font-mono text-xs">{k.prefix}</td>
                  <td className="px-3 py-2">
                    <span
                      className={cn(
                        "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
                        k.enabled
                          ? "bg-green-500/10 text-green-600"
                          : "bg-red-500/10 text-red-500",
                      )}
                    >
                      {k.enabled ? "Active" : "Revoked"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {k.created_at}
                  </td>
                  <td className="px-3 py-2">
                    {k.enabled && (
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleRotate(k.key_id)}
                          className="rounded px-2 py-1 text-xs text-primary hover:bg-primary/10"
                        >
                          Rotate
                        </button>
                        <button
                          onClick={() => handleRevoke(k.key_id)}
                          className="rounded px-2 py-1 text-xs text-destructive hover:bg-destructive/10"
                        >
                          Revoke
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

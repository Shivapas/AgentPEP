/**
 * APEP-343 -- Pattern Library UI
 *
 * Browse and search the enterprise scope pattern library.
 * Displays curated templates organized by category with filtering
 * by risk level, tags, and free-text search.
 */
import { useEffect, useState, useCallback } from "react";
import { listPatterns, getPatternCategories } from "@/api/scope";
import type {
  PatternTemplate,
  PatternCategory,
  PatternRiskLevel,
  CategoryCount,
} from "@/types/scope";
import { cn } from "@/lib/utils";

const RISK_COLORS: Record<string, string> = {
  low: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300",
  critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
};

const CATEGORY_LABELS: Record<string, string> = {
  data_access: "Data Access",
  code_execution: "Code Execution",
  network: "Network",
  secrets: "Secrets",
  admin: "Admin",
  messaging: "Messaging",
  deployment: "Deployment",
  compliance: "Compliance",
  custom: "Custom",
};

function TemplateCard({
  template,
  onSelect,
}: {
  template: PatternTemplate;
  onSelect: (t: PatternTemplate) => void;
}) {
  return (
    <div
      onClick={() => onSelect(template)}
      className="cursor-pointer rounded-lg border border-border bg-card p-4 transition-shadow hover:shadow-md"
    >
      <div className="flex items-start justify-between">
        <h3 className="font-semibold">{template.name}</h3>
        <span
          className={cn(
            "inline-block rounded px-2 py-0.5 text-xs font-semibold",
            RISK_COLORS[template.risk_level] ?? "bg-muted",
          )}
        >
          {template.risk_level}
        </span>
      </div>
      <p className="mt-1 text-sm text-muted-foreground line-clamp-2">{template.description}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {template.tags.slice(0, 4).map((tag) => (
          <span
            key={tag}
            className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground"
          >
            {tag}
          </span>
        ))}
        {template.tags.length > 4 && (
          <span className="text-xs text-muted-foreground">+{template.tags.length - 4} more</span>
        )}
      </div>
      <div className="mt-2 text-xs text-muted-foreground">
        {template.scope_patterns.length} scope pattern{template.scope_patterns.length !== 1 ? "s" : ""}
        {template.checkpoint_patterns.length > 0 && (
          <span>
            {" "}| {template.checkpoint_patterns.length} checkpoint{template.checkpoint_patterns.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}

function TemplateDetail({
  template,
  onBack,
}: {
  template: PatternTemplate;
  onBack: () => void;
}) {
  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="text-sm text-muted-foreground hover:text-foreground"
      >
        Back to library
      </button>

      <div className="flex items-center gap-3">
        <h2 className="text-2xl font-bold">{template.name}</h2>
        <span
          className={cn(
            "inline-block rounded px-2 py-0.5 text-xs font-semibold",
            RISK_COLORS[template.risk_level] ?? "bg-muted",
          )}
        >
          {template.risk_level}
        </span>
        <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
          {CATEGORY_LABELS[template.category] ?? template.category}
        </span>
      </div>

      <p className="text-sm text-muted-foreground">{template.description}</p>

      {/* Scope patterns */}
      <div>
        <h3 className="mb-2 text-sm font-semibold">Scope Patterns</h3>
        <div className="space-y-1">
          {template.scope_patterns.map((p, i) => (
            <div key={i} className="rounded bg-muted px-3 py-1.5 font-mono text-sm">
              {p}
            </div>
          ))}
        </div>
      </div>

      {/* Checkpoint patterns */}
      {template.checkpoint_patterns.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold">Checkpoint Patterns</h3>
          <div className="space-y-1">
            {template.checkpoint_patterns.map((p, i) => (
              <div key={i} className="rounded bg-yellow-50 dark:bg-yellow-900/20 px-3 py-1.5 font-mono text-sm">
                {p}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Use cases */}
      {template.use_cases.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold">Use Cases</h3>
          <ul className="list-inside list-disc text-sm text-muted-foreground">
            {template.use_cases.map((uc, i) => (
              <li key={i}>{uc}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tags */}
      <div className="flex flex-wrap gap-1">
        {template.tags.map((tag) => (
          <span
            key={tag}
            className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground"
          >
            {tag}
          </span>
        ))}
      </div>

      <div className="text-xs text-muted-foreground">
        Author: {template.author} | Version: {template.version}
      </div>
    </div>
  );
}

export function PatternLibrary() {
  const [templates, setTemplates] = useState<PatternTemplate[]>([]);
  const [categories, setCategories] = useState<CategoryCount[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<PatternTemplate | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<PatternCategory | "">("");
  const [riskFilter, setRiskFilter] = useState<PatternRiskLevel | "">("");
  const [searchQuery, setSearchQuery] = useState("");

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [patternsRes, categoriesRes] = await Promise.all([
        listPatterns({
          category: categoryFilter || undefined,
          risk_level: riskFilter || undefined,
          search: searchQuery || undefined,
          limit: 100,
        }),
        getPatternCategories(),
      ]);
      setTemplates(patternsRes.templates);
      setTotal(patternsRes.total);
      setCategories(categoriesRes);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load patterns");
    } finally {
      setLoading(false);
    }
  }, [categoryFilter, riskFilter, searchQuery]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (selectedTemplate) {
    return (
      <TemplateDetail
        template={selectedTemplate}
        onBack={() => setSelectedTemplate(null)}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Pattern Library</h2>
        <p className="text-sm text-muted-foreground">
          Browse {total} curated enterprise scope pattern templates.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search patterns..."
          className="w-64 rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        />
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value as PatternCategory | "")}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        >
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c.category} value={c.category}>
              {CATEGORY_LABELS[c.category] ?? c.category} ({c.count})
            </option>
          ))}
        </select>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value as PatternRiskLevel | "")}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        >
          <option value="">All risk levels</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && <p className="text-sm text-muted-foreground">Loading patterns...</p>}

      {/* Grid */}
      {!loading && templates.length === 0 && (
        <p className="text-sm text-muted-foreground">No patterns found matching your filters.</p>
      )}

      {!loading && templates.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {templates.map((t) => (
            <TemplateCard key={t.template_id} template={t} onSelect={setSelectedTemplate} />
          ))}
        </div>
      )}
    </div>
  );
}

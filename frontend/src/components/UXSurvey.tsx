import { useState } from "react";

/**
 * System Usability Scale (SUS) survey for Policy Console UX study (APEP-214).
 * Target: SUS score > 75.
 *
 * SUS uses 10 standard questions rated 1-5 (Strongly Disagree to Strongly Agree).
 * Score formula: ((sum of odd-item scores - 10) + (40 - sum of even-item scores)) * 2.5
 */

const SUS_QUESTIONS = [
  "I think that I would like to use the Policy Console frequently.",
  "I found the Policy Console unnecessarily complex.",
  "I thought the Policy Console was easy to use.",
  "I think I would need the support of a technical person to use the Policy Console.",
  "I found the various functions in the Policy Console were well integrated.",
  "I thought there was too much inconsistency in the Policy Console.",
  "I would imagine that most people would learn to use the Policy Console very quickly.",
  "I found the Policy Console very cumbersome to use.",
  "I felt very confident using the Policy Console.",
  "I needed to learn a lot of things before I could get going with the Policy Console.",
] as const;

const SCALE_LABELS = [
  "Strongly Disagree",
  "Disagree",
  "Neutral",
  "Agree",
  "Strongly Agree",
] as const;

interface SurveyState {
  responses: (number | null)[];
  additionalFeedback: string;
  submitted: boolean;
  score: number | null;
}

export function UXSurvey() {
  const [state, setState] = useState<SurveyState>({
    responses: Array.from({ length: 10 }, () => null),
    additionalFeedback: "",
    submitted: false,
    score: null,
  });

  const setResponse = (index: number, value: number) => {
    setState((prev) => {
      const responses = [...prev.responses];
      responses[index] = value;
      return { ...prev, responses };
    });
  };

  const calculateSUS = (responses: number[]): number => {
    // SUS scoring: odd questions (1,3,5,7,9) subtract 1; even questions (2,4,6,8,10) 5 - score
    let total = 0;
    for (let i = 0; i < 10; i++) {
      const r = responses[i]!;
      total += i % 2 === 0 ? r - 1 : 5 - r;
    }
    return total * 2.5;
  };

  const allAnswered = state.responses.every((r) => r !== null);

  const handleSubmit = async () => {
    if (!allAnswered) return;

    const score = calculateSUS(state.responses as number[]);

    try {
      await fetch("/api/v1/ux-survey", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          responses: state.responses,
          score,
          additional_feedback: state.additionalFeedback,
          timestamp: new Date().toISOString(),
        }),
      });
    } catch {
      /* submission failure non-blocking */
    }

    setState((prev) => ({ ...prev, submitted: true, score }));
  };

  if (state.submitted) {
    const grade =
      state.score! >= 80.3
        ? "A (Excellent)"
        : state.score! >= 68
          ? "B (Good)"
          : state.score! >= 51
            ? "C (OK)"
            : "D (Needs Improvement)";

    const meetsTarget = state.score! >= 75;

    return (
      <div className="mx-auto max-w-2xl space-y-6">
        <h2 className="text-2xl font-bold">Thank You!</h2>
        <div className="rounded-lg border border-border bg-card p-6 text-center">
          <p className="text-sm text-muted-foreground">Your SUS Score</p>
          <p className={`text-5xl font-bold ${meetsTarget ? "text-green-600" : "text-yellow-600"}`}>
            {state.score!.toFixed(1)}
          </p>
          <p className="mt-2 text-sm text-muted-foreground">Grade: {grade}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Target: 75+ | {meetsTarget ? "Target met" : "Below target"}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h2 className="text-2xl font-bold">UX Feedback Survey</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          System Usability Scale (SUS) — Help us improve the Policy Console.
          Rate each statement from 1 (Strongly Disagree) to 5 (Strongly Agree).
        </p>
      </div>

      <div className="space-y-6">
        {SUS_QUESTIONS.map((question, i) => (
          <div key={i} className="rounded-lg border border-border bg-card p-4">
            <p className="mb-3 text-sm font-medium text-card-foreground">
              {i + 1}. {question}
            </p>
            <div className="flex items-center justify-between gap-2">
              {SCALE_LABELS.map((label, j) => {
                const value = j + 1;
                const selected = state.responses[i] === value;
                return (
                  <button
                    key={j}
                    onClick={() => setResponse(i, value)}
                    className={`flex-1 rounded-md border px-2 py-2 text-xs transition-colors ${
                      selected
                        ? "border-primary bg-primary text-primary-foreground"
                        : "border-border bg-background text-muted-foreground hover:bg-muted"
                    }`}
                  >
                    <div className="font-bold">{value}</div>
                    <div className="mt-0.5 hidden sm:block">{label}</div>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <label className="mb-2 block text-sm font-medium text-card-foreground">
          Additional Feedback (optional)
        </label>
        <textarea
          value={state.additionalFeedback}
          onChange={(e) =>
            setState((prev) => ({ ...prev, additionalFeedback: e.target.value }))
          }
          rows={4}
          placeholder="What could we improve? What worked well?"
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
      </div>

      <button
        onClick={() => void handleSubmit()}
        disabled={!allAnswered}
        className={`w-full rounded-md px-4 py-2 text-sm font-semibold transition-colors ${
          allAnswered
            ? "bg-primary text-primary-foreground hover:bg-primary/90"
            : "cursor-not-allowed bg-muted text-muted-foreground"
        }`}
      >
        {allAnswered ? "Submit Survey" : `Answer all questions (${state.responses.filter((r) => r !== null).length}/10)`}
      </button>
    </div>
  );
}

import { addLog } from "./debug-store.svelte";

export type ToastType = "success" | "error" | "info";

export type ToastItem = {
  id: number;
  type: ToastType;
  message: string;
  closing: boolean;
};

// SECURITY: backend error messages can leak internal filesystem layout
// (absolute paths, usernames, home dirs). Redact absolute paths from the
// user-visible toast while keeping the last path segment (the filename) so the
// message stays meaningful. Debug logs keep the original string.
const ABSOLUTE_PATH_RE =
  /((?:[A-Za-z]:)?[\\/](?:[^\\/\s"']+[\\/])+[^\\/\s"']*)/g;

function sanitizeErrorMessage(message: string): string {
  return message.replace(ABSOLUTE_PATH_RE, (_full, path: string) => {
    const lastSep = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
    const name = lastSep >= 0 ? path.slice(lastSep + 1) : path;
    // keep readable filenames; redact empty/root-only matches
    return name && name !== path ? name : "<path>";
  });
}

const MAX_VISIBLE = 3;
const DEFAULT_DURATION = 5000;
const ERROR_DURATION = 8000;

let nextId = 0;
let toasts: ToastItem[] = $state([]);
const timers = new Map<number, ReturnType<typeof setTimeout>>();

export function getToasts(): ToastItem[] {
  return toasts;
}

export function showToast(type: ToastType, message: string, duration?: number) {
  const id = nextId++;
  const ms = duration ?? (type === "error" ? ERROR_DURATION : DEFAULT_DURATION);

  addLog(type === "error" ? "error" : "info", "system", message);

  const safeMessage = type === "error" ? sanitizeErrorMessage(message) : message;

  toasts = [...toasts, { id, type, message: safeMessage, closing: false }];

  while (toasts.filter((t) => !t.closing).length > MAX_VISIBLE) {
    const oldest = toasts.find((t) => !t.closing);
    if (oldest) dismissToast(oldest.id);
  }

  timers.set(
    id,
    setTimeout(() => dismissToast(id), ms),
  );
}

export function dismissToast(id: number) {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }

  toasts = toasts.map((t) => (t.id === id ? { ...t, closing: true } : t));

  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id);
  }, 200);
}

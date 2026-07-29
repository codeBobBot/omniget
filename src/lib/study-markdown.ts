import DOMPurify from "dompurify";

let markedInstance: typeof import("marked").marked | null = null;
let loadPromise: Promise<typeof import("marked").marked> | null = null;

async function getMarked(): Promise<typeof import("marked").marked> {
  if (markedInstance) return markedInstance;
  if (!loadPromise) {
    loadPromise = import("marked").then((mod) => {
      const m = mod.marked;
      m.setOptions({
        gfm: true,
        breaks: true,
      });
      markedInstance = m;
      return m;
    });
  }
  return loadPromise;
}

/** Sanitize HTML output to prevent XSS via malicious markdown content. */
function sanitize(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      "p", "br", "b", "i", "em", "strong", "a", "ul", "ol", "li",
      "code", "pre", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6",
      "img", "table", "thead", "tbody", "tr", "th", "td", "hr", "del",
      "sup", "sub", "details", "summary", "span", "div",
    ],
    ALLOWED_ATTR: ["href", "src", "alt", "title", "class", "target", "rel"],
    ALLOW_DATA_ATTR: false,
  });
}

export async function renderMarkdown(text: string): Promise<string> {
  if (!text) return "";
  try {
    const m = await getMarked();
    const out = m.parse(text, { async: false }) as string;
    return sanitize(out);
  } catch {
    return escapeHtml(text);
  }
}

export function renderMarkdownSync(
  text: string,
  cache: Map<string, string>,
  onReady?: () => void,
): string {
  if (!text) return "";
  if (cache.has(text)) return cache.get(text)!;
  void renderMarkdown(text).then((html) => {
    cache.set(text, html);
    onReady?.();
  });
  return escapeHtml(text);
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

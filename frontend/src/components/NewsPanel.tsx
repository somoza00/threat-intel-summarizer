import { useEffect, useState } from "react";
import { fetchNews } from "../services/api";
import type { NewsItem } from "../types/intel";

const sourceColors: Record<string, string> = {
  "The Hacker News": "bg-blue-900 text-blue-300",
  "Bleeping Computer": "bg-orange-900 text-orange-300",
  "CISA": "bg-green-900 text-green-300",
};

function formatTime(iso: string | null): string {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return d.toLocaleString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}

export function NewsPanel() {
  const [items, setItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchNews()
      .then(setItems)
      .finally(() => setLoading(false));
  }, []);

  const today = new Date().toLocaleDateString("pt-BR", {
    weekday: "long",
    day: "2-digit",
    month: "long",
  });

  return (
    <aside className="w-72 flex-shrink-0 sticky top-6 self-start">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 space-y-4">
        <div>
          <p className="text-gray-400 text-xs font-semibold uppercase tracking-wider">
            Notícias de Segurança
          </p>
          <p className="text-gray-600 text-xs mt-0.5 capitalize">{today}</p>
        </div>

        {loading && (
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="animate-pulse space-y-1.5">
                <div className="h-3 bg-gray-700 rounded w-full" />
                <div className="h-3 bg-gray-700 rounded w-4/5" />
                <div className="h-2 bg-gray-800 rounded w-1/3 mt-1" />
              </div>
            ))}
          </div>
        )}

        {!loading && items.length === 0 && (
          <p className="text-gray-500 text-xs">Não foi possível carregar as notícias.</p>
        )}

        {!loading && items.length > 0 && (
          <div className="space-y-4 max-h-[calc(100vh-10rem)] overflow-y-auto pr-1 scrollbar-thin">
            {items.map((item, i) => {
              const colorClass = sourceColors[item.source] ?? "bg-gray-800 text-gray-400";
              return (
                <div key={i} className="space-y-1 border-b border-gray-800 pb-3 last:border-0 last:pb-0">
                  <a
                    href={item.link}
                    target="_blank"
                    rel="noreferrer"
                    className="text-white text-xs font-medium leading-snug hover:text-blue-400 transition-colors line-clamp-3"
                  >
                    {item.title}
                  </a>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${colorClass}`}>
                      {item.source}
                    </span>
                    {item.published_at && (
                      <span className="text-gray-600 text-[10px]">
                        {formatTime(item.published_at)}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </aside>
  );
}

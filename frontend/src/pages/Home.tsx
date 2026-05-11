import { useState } from "react";
import { analyze } from "../services/api";
import { ResultCard } from "../components/ResultCard";
import type { AnalyzeResponse } from "../types/intel";

export function Home() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyze(query.trim());
      setResult(data);
    } catch (err: unknown) {
      setError("Erro ao analisar. Verifique o input e tente novamente.");
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") handleAnalyze();
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="max-w-2xl mx-auto space-y-8">

        <div className="text-center space-y-2">
          <h1 className="text-3xl font-bold text-white">Threat Intel Summarizer</h1>
          <p className="text-gray-400">Analise IPs, hashes, domínios e CVEs em segundos</p>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ex: 1.1.1.1 | CVE-2021-44228 | malware.exe hash..."
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-6 py-3 rounded-lg font-semibold transition-colors"
          >
            {loading ? "Analisando..." : "Analisar"}
          </button>
        </div>

        {error && (
          <div className="bg-red-900 border border-red-700 rounded-lg p-4 text-red-300 text-sm">
            {error}
          </div>
        )}

        {result && <ResultCard result={result} />}

      </div>
    </div>
  );
}
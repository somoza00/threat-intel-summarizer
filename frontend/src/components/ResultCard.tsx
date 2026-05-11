import type { AnalyzeResponse } from "../types/intel";
import { RiskBadge } from "./RiskBadge";
import { FindingCard } from "./FindingCard";

interface Props {
  result: AnalyzeResponse;
}

export function ResultCard({ result }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 space-y-6">
      
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-400 text-sm">Análise de</p>
          <p className="text-white font-mono text-lg break-all">{result.query}</p>
          <p className="text-gray-500 text-xs uppercase mt-1">{result.input_type}</p>
        </div>
        <RiskBadge level={result.risk_level} score={result.risk_score} />
      </div>

      <div>
        <h2 className="text-gray-400 text-sm font-medium mb-2">Resumo</h2>
        <p className="text-gray-200 text-sm leading-relaxed">{result.summary}</p>
      </div>

      {result.findings.length > 0 && (
        <div>
          <h2 className="text-gray-400 text-sm font-medium mb-3">Findings</h2>
          <div className="space-y-3">
            {result.findings.map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
          </div>
        </div>
      )}

      {result.recommendations.length > 0 && (
        <div>
          <h2 className="text-gray-400 text-sm font-medium mb-3">Recomendações</h2>
          <ul className="space-y-2">
            {result.recommendations.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                <span className="text-green-400 mt-0.5">→</span>
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}

    </div>
  );
}
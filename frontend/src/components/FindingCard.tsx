import { useState } from "react";
import type { Finding } from "../types/intel";

interface Props {
  finding: Finding;
}

const sourceColors: Record<string, string> = {
  VirusTotal: "bg-blue-900 text-blue-300",
  AbuseIPDB: "bg-purple-900 text-purple-300",
  NVD: "bg-red-900 text-red-300",
};

export function FindingCard({ finding }: Props) {
  const [expanded, setExpanded] = useState(false);
  const colorClass = sourceColors[finding.source] ?? "bg-gray-800 text-gray-300";

  return (
    <div
      className="border border-gray-700 rounded-lg p-4 bg-gray-800 cursor-pointer select-none"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center justify-between">
        <h3 className="text-white font-semibold">{finding.title}</h3>
        <div className="flex items-center gap-2">
          <span className={`text-xs px-2 py-1 rounded-full font-medium ${colorClass}`}>
            {finding.source}
          </span>
          <span className="text-gray-400 text-sm">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {expanded && (
        <p className="text-gray-400 text-sm mt-3 leading-relaxed">
          {finding.description}
        </p>
      )}
    </div>
  );
}
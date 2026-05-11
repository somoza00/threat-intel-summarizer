import type { RiskLevel } from "../types/intel";

interface Props {
  level: RiskLevel;
  score?: number | null;
}

const config: Record<RiskLevel, { label: string; classes: string }> = {
  critical: { label: "Critical", classes: "bg-red-600 text-white" },
  high:     { label: "High",     classes: "bg-orange-500 text-white" },
  medium:   { label: "Medium",   classes: "bg-yellow-400 text-black" },
  low:      { label: "Low",      classes: "bg-blue-500 text-white" },
  clean:    { label: "Clean",    classes: "bg-green-500 text-white" },
  unknown:  { label: "Unknown",  classes: "bg-gray-500 text-white" },
};

export function RiskBadge({ level, score }: Props) {
  const { label, classes } = config[level];
  return (
    <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-semibold ${classes}`}>
      {label}
      {score !== null && score !== undefined && (
        <span className="opacity-80">({score.toFixed(1)})</span>
      )}
    </span>
  );
}
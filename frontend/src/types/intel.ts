export type RiskLevel = "critical" | "high" | "medium" | "low" | "clean" | "unknown";

export interface NewsItem {
  title: string;
  link: string;
  published_at: string | null;
  description: string;
  source: string;
}
export type InputType = "ip" | "hash" | "domain" | "cve";

export interface Finding {
  title: string;
  description: string;
  source: string;
}

export interface AnalyzeResponse {
  query: string;
  input_type: InputType;
  risk_level: RiskLevel;
  risk_score: number | null;
  summary: string;
  findings: Finding[];
  recommendations: string[];
  raw_data: Record<string, unknown>;
  country?: string;
}
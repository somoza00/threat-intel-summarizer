import axios from "axios";
import type { AnalyzeResponse } from "../types/intel";

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
});

export async function analyze(query: string): Promise<AnalyzeResponse> {
  const { data } = await client.post<AnalyzeResponse>("/api/analyze", { query });
  return data;
}

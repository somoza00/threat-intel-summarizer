import axios from "axios";
import type { AnalyzeResponse, NewsItem } from "../types/intel";

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
});

export async function analyze(query: string): Promise<AnalyzeResponse> {
  const { data } = await client.post<AnalyzeResponse>("/api/analyze", { query });
  return data;
}

export async function fetchNews(): Promise<NewsItem[]> {
  const { data } = await client.get<{ items: NewsItem[] }>("/api/news");
  return data.items;
}

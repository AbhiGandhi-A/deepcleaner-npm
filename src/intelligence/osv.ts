export interface OsvPackageQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version: string;
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
    versions?: string[];
  }>;
}

export interface OsvBatchResult {
  vulns?: OsvVulnerability[];
}

export async function queryOsvBatch(
  queries: OsvPackageQuery[],
  timeoutMs = 15000
): Promise<Map<string, OsvVulnerability[]>> {
  const results = new Map<string, OsvVulnerability[]>();
  if (queries.length === 0) return results;

  const batchSize = 500;
  for (let i = 0; i < queries.length; i += batchSize) {
    const chunk = queries.slice(i, i + batchSize);
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const res = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: chunk }),
        signal: controller.signal
      });

      clearTimeout(timer);

      if (!res.ok) {
        continue;
      }

      const data = (await res.json()) as { results?: OsvBatchResult[] };
      if (data.results && Array.isArray(data.results)) {
        for (let j = 0; j < chunk.length; j++) {
          const q = chunk[j];
          const queryKey = `${q.package.ecosystem.toLowerCase()}:${q.package.name.toLowerCase()}@${q.version}`;
          const itemResult = data.results[j];
          if (itemResult && itemResult.vulns && itemResult.vulns.length > 0) {
            results.set(queryKey, itemResult.vulns);
          }
        }
      }
    } catch {
      break;
    }
  }

  return results;
}

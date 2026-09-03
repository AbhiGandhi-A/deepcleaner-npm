import type { ScanContext } from '../core/context.js';
import type { Finding } from '../models/finding.js';
import { GroqClient } from './groq.js';
import { sanitizeFindingForAI } from './redaction.js';
import { mapConcurrent } from '../core/scheduler.js';

export interface AiEnrichmentResult {
  status: 'completed' | 'skipped' | 'unavailable' | 'error';
  message: string;
  enrichedCount: number;
}

export async function runAiFindingAnalysis(ctx: ScanContext, findings: Finding[]): Promise<AiEnrichmentResult> {
  const client = new GroqClient(undefined, ctx.userConfig.ai?.model);

  if (!client.isConfigured()) {
    return {
      status: 'skipped',
      message: 'AI analysis skipped: GROQ_API_KEY is not configured.',
      enrichedCount: 0
    };
  }

  const candidateFindings = findings.filter(
    (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.category === 'Security' || f.category === 'Malware'
  ).slice(0, 15);

  if (candidateFindings.length === 0) {
    return {
      status: 'completed',
      message: 'AI analysis completed (no candidate high-severity findings required verification).',
      enrichedCount: 0
    };
  }

  ctx.logger.verbose(`Analyzing ${candidateFindings.length} findings with Groq AI...`);
  let enrichedCount = 0;

  try {
    await mapConcurrent(candidateFindings, 3, async (finding) => {
      try {
        const sanitized = sanitizeFindingForAI(finding);
        const result = await client.analyzeFinding(sanitized);
        if (result) {
          finding.aiAnalysis = {
            verdict: result.verdict,
            confidence: result.confidence,
            severity: result.severity,
            explanation: result.explanation,
            attackPath: result.attackPath,
            recommendation: result.recommendation,
            reasoningSummary: result.reasoningSummary
          };
          enrichedCount++;
        }
      } catch (err: any) {
        ctx.logger.verbose(`AI analysis failed for finding ${finding.id}: ${err?.message || err}`);
      }
    });

    return {
      status: 'completed',
      message: `AI analysis completed: ${enrichedCount} findings enriched with advisory insights.`,
      enrichedCount
    };
  } catch (err: any) {
    if (err?.message?.includes('rate limit')) {
      return {
        status: 'unavailable',
        message: 'AI analysis temporarily unavailable due to API rate limits. Deterministic findings preserved.',
        enrichedCount
      };
    }
    return {
      status: 'error',
      message: `AI analysis error: ${err?.message || err}`,
      enrichedCount
    };
  }
}

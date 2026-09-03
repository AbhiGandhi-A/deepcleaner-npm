import { APPSEC_SYSTEM_PROMPT, createFindingAnalysisPrompt } from './prompts.js';
import type { SanitizedFindingContext } from './redaction.js';

export interface GroqAnalysisResult {
  verdict: 'confirmed' | 'likely' | 'suspicious' | 'false_positive' | 'unknown';
  confidence: number;
  severity: string;
  explanation: string;
  attackPath?: string[];
  recommendation: string;
  reasoningSummary: string;
}

export class GroqClient {
  private apiKey: string | undefined;
  private model: string;

  constructor(apiKey?: string, model = 'llama-3.3-70b-versatile') {
    this.apiKey = apiKey || process.env.GROQ_API_KEY;
    this.model = model;
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  async analyzeFinding(finding: SanitizedFindingContext, timeoutMs = 25000): Promise<GroqAnalysisResult | null> {
    if (!this.isConfigured()) {
      return null;
    }

    const prompt = createFindingAnalysisPrompt(finding);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.model,
          messages: [
            { role: 'system', content: APPSEC_SYSTEM_PROMPT },
            { role: 'user', content: prompt }
          ],
          response_format: { type: 'json_object' },
          temperature: 0.1
        }),
        signal: controller.signal
      });

      clearTimeout(timer);

      if (!response.ok) {
        if (response.status === 429) {
          throw new Error('Groq rate limit reached');
        }
        throw new Error(`Groq API returned status ${response.status}`);
      }

      const json = (await response.json()) as any;
      const content = json.choices?.[0]?.message?.content;
      if (!content) return null;

      const parsed = JSON.parse(content);
      return {
        verdict: parsed.verdict || 'unknown',
        confidence: typeof parsed.confidence === 'number' ? Math.min(100, Math.max(0, parsed.confidence)) : 50,
        severity: parsed.severity || finding.severity,
        explanation: parsed.explanation || '',
        attackPath: Array.isArray(parsed.attack_path) ? parsed.attack_path : undefined,
        recommendation: parsed.recommendation || '',
        reasoningSummary: parsed.reasoning_summary || ''
      };
    } catch (err: any) {
      if (err.name === 'AbortError') {
        throw new Error('Groq request timed out');
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}

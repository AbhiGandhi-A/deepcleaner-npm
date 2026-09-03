import type { ScanResult } from '../models/scan-result.js';
import type { Finding } from '../models/finding.js';
import { ALL_RULES } from '../rules/index.js';

export function renderSarifReport(result: ScanResult): string {
  const sarifRules = ALL_RULES.map((rule) => ({
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.name },
    fullDescription: { text: rule.description },
    helpUri: rule.references?.[0] || 'https://github.com/AbhiGandhi-A/deepcleaner-npm#readme',
    help: {
      text: `${rule.description}\n\nRemediation: ${rule.remediation}`
    },
    defaultConfiguration: {
      level: mapSeverityToSarifLevel(rule.defaultSeverity)
    }
  }));

  const results = result.findings.map((f: Finding) => ({
    ruleId: f.id,
    level: mapSeverityToSarifLevel(f.severity),
    message: {
      text: `${f.title}: ${f.description}`
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.file,
            uriBaseId: '%SRCROOT%'
          },
          region: {
            startLine: f.line || 1,
            startColumn: f.column || 1,
            snippet: f.redactedEvidence ? { text: f.redactedEvidence } : undefined
          }
        }
      }
    ]
  }));

  const sarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: result.tool.name,
            version: result.tool.version,
            informationUri: result.tool.homepage,
            rules: sarifRules
          }
        },
        results
      }
    ]
  };

  return JSON.stringify(sarifLog, null, 2);
}

function mapSeverityToSarifLevel(sev: string): 'error' | 'warning' | 'note' {
  switch (sev) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    default:
      return 'note';
  }
}

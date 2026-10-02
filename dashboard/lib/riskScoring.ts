//C:\Users\hp\aiops-securewatch\dashboard\lib\riskScoring.ts
import {
  CIS_BENCHMARK_MATRIX,
  detectVendor,
  VendorType,
  SeverityLevel,
  CISBenchmarkRule,
  ValidatedFinding,
} from './cisBenchmarks';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const RISK_RANKS: Record<RiskLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

export function normalizeRiskLevel(val?: string): RiskLevel {
  const normalized = String(val || '').toUpperCase().trim();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
    return normalized as RiskLevel;
  }
  if (normalized === 'CRIT') return 'CRITICAL';
  if (normalized === 'MED') return 'MEDIUM';
  if (normalized === 'INFORMATIONAL' || normalized === 'INFO') return 'LOW';
  return 'LOW';
}

export function getHighestRiskLevel(riskA: RiskLevel, riskB: RiskLevel): RiskLevel {
  const rankA = RISK_RANKS[riskA] ?? 1;
  const rankB = RISK_RANKS[riskB] ?? 1;
  return rankA >= rankB ? riskA : riskB;
}

export interface RawFindingInput {
  ruleId?: string;
  category?: string;
  title?: string;
  description?: string;
  remediation_cli?: string;
  remediationCli?: string;
  severity?: string;
}

export interface RuleEngineResult {
  riskLevel: RiskLevel;
  findings: ValidatedFinding[];
}

/**
 * Process AI scan findings through CIS benchmark validation.
 * Preserves AI-detected severity for non-matrix custom vulnerabilities.
 */
export function processScanFindings(
  rawFindings: RawFindingInput[],
  rawVendorInput: string = 'cisco_ios'
): RuleEngineResult {
  if (!rawFindings || !Array.isArray(rawFindings) || rawFindings.length === 0) {
    return { riskLevel: 'LOW', findings: [] };
  }

  const vendor: VendorType = detectVendor(rawVendorInput);
  const evaluatedFindings: ValidatedFinding[] = [];

  for (const raw of rawFindings) {
    let matchedRule: CISBenchmarkRule | undefined = undefined;

    // 1. Direct Rule ID match
    if (raw.ruleId) {
      const cleanRuleId = raw.ruleId.trim().toUpperCase();
      matchedRule = CIS_BENCHMARK_MATRIX.find(
        (r) => r.ruleId.toUpperCase() === cleanRuleId
      );
    }

    // 2. Fallback: Search via textual keywords
    if (!matchedRule) {
      const rawText = `${raw.title || ''} ${raw.description || ''} ${raw.category || ''}`.toLowerCase();

      for (const rule of CIS_BENCHMARK_MATRIX) {
        if (rawText.includes(rule.ruleId.toLowerCase())) {
          matchedRule = rule;
          break;
        }

        const vConfig = rule.vendors[vendor] || rule.vendors['generic'];
        if (!vConfig) continue;

        const matchFound = vConfig.detectionKeys.some((key: string) => {
          return rawText.includes(key.toLowerCase());
        });

        if (matchFound) {
          matchedRule = rule;
          break;
        }
      }
    }

    // 3. Construct finding with normalized schema
    if (matchedRule) {
      const vConfig = matchedRule.vendors[vendor] || matchedRule.vendors['generic'];
      evaluatedFindings.push({
        ruleId: matchedRule.ruleId,
        title: matchedRule.title,
        description: matchedRule.description,
        severity: matchedRule.severity,
        cisControl: matchedRule.cisControl,
        remediationCli: raw.remediation_cli || raw.remediationCli || (vConfig ? vConfig.remediationCli : ''),
      });
    } else {
      // Preserve AI severity for generic/custom threats rather than downgrading to LOW
      const aiSeverity = normalizeRiskLevel(raw.severity);
      evaluatedFindings.push({
        ruleId: raw.ruleId || 'GENERIC-CIS-4',
        title: raw.title || 'Security Configuration Finding',
        description: raw.description || 'General security finding requiring administrative review.',
        severity: aiSeverity,
        cisControl: 'CIS Control 4: Secure Configuration',
        remediationCli: raw.remediation_cli || raw.remediationCli || 'Review configuration policy.',
      });
    }
  }

  // Calculate highest severity floor
  let overallRisk: RiskLevel = 'LOW';
  for (const finding of evaluatedFindings) {
    overallRisk = getHighestRiskLevel(overallRisk, finding.severity);
  }

  return {
    riskLevel: overallRisk,
    findings: evaluatedFindings,
  };
}
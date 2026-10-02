// dashboard/lib/sanitizer.ts
// dashboard/lib/sanitizer.ts
import patternSpec from '../../shared/redaction-patterns.json';

export interface TokenizedResult {
  sanitizedConfig: string;
  tokens: Record<string, string>;
}

type PatternMode = 'wholeMatch' | 'group' | 'quoted';

interface RedactionPattern {
  id: string;
  description: string;
  regex: string;
  flags: string;
  mode: PatternMode;
  tokenCategory: string;
  secretGroup?: number;
  prefixGroups?: number[];
  quoteGroup?: number;
}

const PATTERNS = (patternSpec.patterns || []) as RedactionPattern[];
const TOKEN_PATTERN = /__TOKEN_[A-Z0-9_]+_\d+__/g;

/**
 * Helper to construct RegExp with enforced global matching ('g')
 */
function buildRegex(pattern: RedactionPattern): RegExp {
  const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
  return new RegExp(pattern.regex, flags);
}

/**
 * 1. REVERSIBLE TOKENIZATION
 * Replaces credentials with unique tokens (__TOKEN_...__) and returns a lookup table.
 * Deduplicates identical secrets and guards against token contamination and trailing truncation.
 */
export function tokenizeConfig(configText: string): TokenizedResult {
  if (!configText || configText.trim() === '' || configText.trim() === '!') {
    return { sanitizedConfig: configText || '', tokens: {} };
  }

  const tokens: Record<string, string> = {};
  const secretToTokenMap = new Map<string, string>();
  let sanitizedConfig = configText;
  let counter = 1;

  const createToken = (secretValue: string, category: string): string => {
    if (!secretValue || secretValue.trim() === '' || secretValue === '!') return secretValue;

    // Prevent re-tokenizing an existing token
    if (secretValue.startsWith('__TOKEN_') && secretValue.endsWith('__')) {
      return secretValue;
    }

    // Deduplicate identical secrets
    if (secretToTokenMap.has(secretValue)) {
      return secretToTokenMap.get(secretValue)!;
    }

    const tokenId = `__TOKEN_${category}_${counter++}__`;
    tokens[tokenId] = secretValue;
    secretToTokenMap.set(secretValue, tokenId);
    return tokenId;
  };

  for (const p of PATTERNS) {
    try {
      const re = buildRegex(p);

      if (p.mode === 'wholeMatch') {
        sanitizedConfig = sanitizedConfig.replace(re, (match) => {
          if (match.includes('__TOKEN_')) return match;
          return createToken(match, p.tokenCategory);
        });
        continue;
      }

      if (p.mode === 'group') {
        sanitizedConfig = sanitizedConfig.replace(re, (...args) => {
          const fullMatch = args[0] as string;
          if (fullMatch.includes('__TOKEN_')) return fullMatch;

          const groups = args.slice(1, -2) as string[];
          const secretIdx = (p.secretGroup as number) - 1;
          const secretValue = groups[secretIdx];
          if (!secretValue) return fullMatch;

          const prefix = (p.prefixGroups || [])
            .map((g) => groups[g - 1] ?? '')
            .join('');

          // Preserve trailing CLI syntax within fullMatch after secretGroup
          const secretPos = fullMatch.indexOf(secretValue);
          const suffix = secretPos !== -1 ? fullMatch.slice(secretPos + secretValue.length) : '';

          return `${prefix}${createToken(secretValue, p.tokenCategory)}${suffix}`;
        });
        continue;
      }

      if (p.mode === 'quoted') {
        sanitizedConfig = sanitizedConfig.replace(re, (...args) => {
          const fullMatch = args[0] as string;
          if (fullMatch.includes('__TOKEN_')) return fullMatch;

          const groups = args.slice(1, -2) as string[];
          const secretIdx = (p.secretGroup as number) - 1;
          const secretValue = groups[secretIdx];
          if (!secretValue) return fullMatch;

          const quote = groups[(p.quoteGroup as number) - 1] || '"';
          const prefix = (p.prefixGroups || [])
            .map((g) => groups[g - 1] ?? '')
            .join('');

          const secretPos = fullMatch.indexOf(secretValue);
          const suffix = secretPos !== -1 ? fullMatch.slice(secretPos + secretValue.length + quote.length) : '';

          return `${prefix}${quote}${createToken(secretValue, p.tokenCategory)}${quote}${suffix}`;
        });
        continue;
      }
    } catch (err) {
      console.warn(`[!] Error processing pattern ${p.id}:`, err);
    }
  }

  return { sanitizedConfig, tokens };
}

/**
 * 2. UNMASKING / DETOKENIZATION
 * Restores original secrets into the sanitized string using key-length sorting to avoid partial key overlaps.
 */
export function detokenizeConfig(sanitizedText: string, tokens: Record<string, string>): string {
  if (!sanitizedText || !tokens || Object.keys(tokens).length === 0) {
    return sanitizedText;
  }

  let restoredConfig = sanitizedText;

  // Sort tokens by key length descending to prevent __TOKEN_X_1 replacing __TOKEN_X_10
  const sortedTokens = Object.entries(tokens).sort(([a], [b]) => b.length - a.length);

  for (const [tokenId, originalValue] of sortedTokens) {
    restoredConfig = restoredConfig.replaceAll(tokenId, originalValue);
  }

  return restoredConfig;
}

/**
 * 3. ONE-WAY SANITIZATION (lossy, permanent)
 * Permanent redactor for LLM prompts and external integrations.
 */
export function sanitizeConfig(configText: string): string {
  if (!configText || configText.trim() === '' || configText.trim() === '!') {
    return configText || '';
  }
  const { sanitizedConfig } = tokenizeConfig(configText);
  return sanitizedConfig.replace(TOKEN_PATTERN, '[REDACTED]');
}

import { PatternDefinition } from './types';

export const financialInformationPatterns: Record<string, PatternDefinition> = {
  CREDIT_CARD: {
    pattern: /\b(?:\d{4}[- ]?){4}\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Credit card numbers should never be shared in plain text.'
  },
  BANK_ACCOUNT: {
    pattern: /\b(?:Account|Routing)\s*(?:Number|#)?\s*:?\s*\d{8,17}\b/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Bank account information should never be shared in plain text.'
  }
};


import { PatternDefinition } from './types';

export const contactInformationPatterns: Record<string, PatternDefinition> = {
  PHONE: {
    pattern: /\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b/g,
    type: 'credential',
    riskLevel: 'medium',
    explanation: 'Phone numbers are personal contact information that should be handled carefully.'
  },
  EMAIL: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    type: 'credential',
    riskLevel: 'medium',
    explanation: 'Email addresses are personal contact information that should be handled carefully.'
  },
  ADDRESS: {
    pattern: /\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Circle|Cir|Trail|Trl),?\s+[A-Za-z\s]+,?\s+[A-Z]{2}\b/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Physical addresses are sensitive personal information that should not be shared.'
  }
};


import { PatternDefinition } from './types';

export const personalIdentifierPatterns: Record<string, PatternDefinition> = {
  SSN: {
    pattern: /\b(?:\d{3}-\d{2}-\d{4}|\d{3}[.-]?\d{2}[.-]?\d{4})\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Social Security Numbers (SSN) are highly sensitive personal identifiers that should never be shared.'
  },
  LABELED_SSN: {
    pattern: /\b(?:ssn|social\s*security(?:\s*number)?)\s*:?\s*\d{3}-?\d{2}-?\d{4}\b/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Labeled Social Security Numbers are highly sensitive personal identifiers that should never be shared.'
  },
  DRIVERS_LICENSE: {
    pattern: /\b(?:[A-Z]\d{7}|[A-Z]\d{3}-\d{3}-\d{4})\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Driver\'s license numbers are sensitive personal identifiers that should not be shared.'
  },
  LICENSE_NO: {
    pattern: /\b(?:License\s+No\.?|DL\s+Number):\s*[A-Z]\d{3}-\d{3}-\d{4}\b/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Driver\'s license numbers are sensitive personal identifiers that should not be shared.'
  },
  PASSPORT: {
    pattern: /\b[A-Z]\d{8}\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Passport numbers are highly sensitive personal identifiers that should not be shared.'
  },
  DOB: {
    pattern: /\b(?:0?[1-9]|1[0-2])[\/.-](0?[1-9]|[12]\d|3[01])[\/.-](?:19|20)\d{2}\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Dates of birth are sensitive personal information that could be used for identity theft.'
  },
  LABELED_DOB: {
    pattern: /\b(?:dob|date\s*of\s*birth|birth\s*date)\s*:?\s*(?:0?[1-9]|1[0-2])[\/.-](?:0?[1-9]|[12]\d|3[01])[\/.-](?:19|20)\d{2}\b/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Labeled dates of birth are sensitive personal information that could be used for identity theft.'
  },
  TIN: {
    pattern: /\b\d{2}[-–]\d{7}\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Tax Identification Numbers are sensitive financial identifiers that should not be shared.'
  }
};

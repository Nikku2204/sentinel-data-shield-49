
import { PatternDefinition } from './types';

export const businessInformationPatterns: Record<string, PatternDefinition> = {
  CLIENT_LIST: {
    pattern: /\bClient(?:\s+List)?:\s*(?:[A-Za-z]+(?:,\s*)?)+/gi,
    type: 'proprietary',
    riskLevel: 'medium',
    explanation: 'Client lists are confidential business information.'
  },
  PROJECT_CODE: {
    pattern: /\bProject\s+Code:\s*[A-Za-z0-9-]+\s*(?:-\s*(?:Top\s+Secret|Confidential))?\b/gi,
    type: 'proprietary',
    riskLevel: 'high',
    explanation: 'Internal project codes and classifications should remain confidential.'
  },
  NDA_CONTENT: {
    pattern: /\b(?:NDA|Non-Disclosure)\s+(?:Agreement|Clause):[^.]+\b/gi,
    type: 'proprietary',
    riskLevel: 'high',
    explanation: 'NDA content is confidential and should not be shared.'
  },
  INTERNAL_DOMAIN: {
    pattern: /(?:internal|corp|intranet|private)\.[\w-]+\.[a-z]{2,}/gi,
    type: 'internal_domain',
    riskLevel: 'medium',
    explanation: 'Internal domain names can reveal details about your organization\'s infrastructure.'
  },
  PROPRIETARY_MARKER: {
    pattern: /(?:confidential|proprietary|internal[_-]?use[_-]?only|do[_-]?not[_-]?share)/gi,
    type: 'proprietary',
    riskLevel: 'medium',
    explanation: 'This appears to be marked as proprietary or confidential information.'
  }
};

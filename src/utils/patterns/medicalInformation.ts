
import { PatternDefinition } from './types';

export const medicalInformationPatterns: Record<string, PatternDefinition> = {
  PATIENT_ID: {
    pattern: /\b(?:Patient\s*ID|MRN)[-:]?\s*\d+\b/gi,
    type: 'proprietary',
    riskLevel: 'high',
    explanation: 'Patient IDs are protected health information covered by privacy regulations.'
  },
  PATIENT_INFO: {
    pattern: /\b(?:patient\s*info|patient\s*information|medical\s*record)\b/gi,
    type: 'proprietary',
    riskLevel: 'high',
    explanation: 'Patient information is protected health data that should not be shared with external services.'
  },
  DIAGNOSIS: {
    pattern: /\bDiagnosis:\s*[A-Za-z\s]+(?:\s+(?:Type|Stage|Grade)\s+[IVX\d]+)?\b/gi,
    type: 'proprietary',
    riskLevel: 'high',
    explanation: 'Medical diagnoses are protected health information that should not be shared.'
  },
  INSURANCE_ID: {
    pattern: /\b(?:[A-Za-z]+\s*#\s*\d+)\b/g,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Insurance ID numbers are sensitive personal information that should not be shared.'
  },
  PRESCRIPTION: {
    pattern: /\b[A-Za-z]+\s+\d+(?:mg|ML|g)\b/gi,
    type: 'proprietary',
    riskLevel: 'high',
    explanation: 'Prescription information is protected health data that should not be shared.'
  }
};

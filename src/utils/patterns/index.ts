
import { PatternDefinition } from './types';
import { personalIdentifierPatterns } from './personalIdentifiers';
import { contactInformationPatterns } from './contactInformation';
import { medicalInformationPatterns } from './medicalInformation';
import { financialInformationPatterns } from './financialInformation';
import { credentialsAndKeysPatterns } from './credentialsAndKeys';
import { businessInformationPatterns } from './businessInformation';
import { miscInformationPatterns } from './miscInformation';

// Combine all pattern categories into a single pattern collection
export const PATTERNS: Record<string, PatternDefinition> = {
  ...personalIdentifierPatterns,
  ...contactInformationPatterns,
  ...medicalInformationPatterns,
  ...financialInformationPatterns,
  ...credentialsAndKeysPatterns,
  ...businessInformationPatterns,
  ...miscInformationPatterns
};

export type { PatternDefinition };
export { personalIdentifierPatterns };
export { contactInformationPatterns };
export { medicalInformationPatterns };
export { financialInformationPatterns };
export { credentialsAndKeysPatterns };
export { businessInformationPatterns };
export { miscInformationPatterns };

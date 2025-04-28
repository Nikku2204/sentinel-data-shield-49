
// Re-export the scanner functionality from the new modular structure
export { scanForSensitiveData, analyzeRiskLevel } from './scannerCore';
export type { Detection } from './patterns/types';

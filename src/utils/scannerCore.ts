
import { Detection } from './patterns/types';
import { PATTERNS } from './patterns';

// Detects if text contains sensitive information
export const scanForSensitiveData = (text: string): Detection[] => {
  const detections: Detection[] = [];
  
  // Function to add a detection
  const addDetection = (
    type: Detection['type'], 
    match: RegExpExecArray, 
    riskLevel: Detection['riskLevel'],
    explanation: string
  ) => {
    detections.push({
      id: `${type}-${detections.length}-${Date.now()}`,
      type,
      content: match[0],
      startIndex: match.index,
      endIndex: match.index + match[0].length,
      riskLevel,
      explanation
    });
  };
  
  // Reset all regex indices
  Object.values(PATTERNS).forEach(patternDef => patternDef.pattern.lastIndex = 0);
  
  // Check for each pattern
  for (const [patternName, patternDef] of Object.entries(PATTERNS)) {
    let match: RegExpExecArray | null;
    while ((match = patternDef.pattern.exec(text)) !== null) {
      addDetection(
        patternDef.type,
        match,
        patternDef.riskLevel,
        patternDef.explanation
      );
    }
  }
  
  return detections;
};

// Analyze the overall risk level of the text
export const analyzeRiskLevel = (detections: Detection[]): 'safe' | 'warning' | 'danger' => {
  if (detections.length === 0) return 'safe';
  
  const hasHighRisk = detections.some(d => d.riskLevel === 'high');
  const hasMediumRisk = detections.some(d => d.riskLevel === 'medium');
  
  if (hasHighRisk) return 'danger';
  if (hasMediumRisk) return 'warning';
  return 'warning'; // Even low risk detections warrant some caution
};

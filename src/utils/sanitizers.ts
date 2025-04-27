
import { Detection } from './scanners';

// Replace sensitive data with safe placeholders
export const sanitizeText = (text: string, detections: Detection[]): string => {
  if (detections.length === 0) return text;
  
  // Sort detections by startIndex in descending order to avoid changing indices
  const sortedDetections = [...detections].sort((a, b) => b.startIndex - a.startIndex);
  
  let result = text;
  
  for (const detection of sortedDetections) {
    const placeholderMap: Record<Detection['type'], string> = {
      api_key: '[API_KEY_REDACTED]',
      sql_query: '[SQL_QUERY_REDACTED]',
      credential: '[CREDENTIALS_REDACTED]',
      internal_domain: '[DOMAIN_REDACTED]',
      proprietary: '[PROPRIETARY_INFO_REDACTED]',
    };
    
    // Replace the sensitive content with a placeholder
    result = 
      result.substring(0, detection.startIndex) + 
      placeholderMap[detection.type] + 
      result.substring(detection.endIndex);
  }
  
  return result;
};

// Generate alternative ways to present the information safely
export const generateSafeAlternatives = (detection: Detection): string[] => {
  switch(detection.type) {
    case 'api_key':
      return [
        "Use a placeholder or variable name like 'YOUR_API_KEY'",
        "Describe the API functionality without including the actual key",
        "Use environment variables to store keys when discussing code"
      ];
    
    case 'sql_query':
      return [
        "Replace table names with generic placeholders like 'table1', 'table2'",
        "Use pseudocode to explain the query logic instead",
        "Remove WHERE clauses that may contain business logic or data filtering criteria"
      ];
      
    case 'credential':
      return [
        "Use placeholders like 'YOUR_PASSWORD' instead of actual credentials",
        "Describe authentication process without including actual credentials",
        "Use masked values like '********' when discussing password formats"
      ];
    
    case 'internal_domain':
      return [
        "Replace with example.com or use [COMPANY_DOMAIN] as a placeholder",
        "Use generic terms like 'internal network' or 'company intranet'",
        "Remove references to specific subdomains or network segments"
      ];
      
    case 'proprietary':
      return [
        "Generalize the information without specific details",
        "Focus on the problem rather than proprietary solutions",
        "Describe functionality abstractly without revealing implementation details"
      ];
    
    default:
      return ["Remove this sensitive information entirely", "Replace with a generic placeholder"];
  }
};

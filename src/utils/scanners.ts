
export interface Detection {
  id: string;
  type: 'api_key' | 'sql_query' | 'credential' | 'internal_domain' | 'proprietary';
  content: string;
  startIndex: number;
  endIndex: number;
  riskLevel: 'high' | 'medium' | 'low';
  explanation: string;
}

// Regular expressions for different types of sensitive information
const PATTERNS = {
  SSN: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
  DOB: /\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b/g,
  API_KEY: /(?:api[_-]?key|access[_-]?token|secret|token|key)[=:]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
  NAMED_API_KEY: /\w+(?:[_-]?(?:api|key|token|secret))(?:\s*[=:]\s*|\s*=\s*|\s+=\s*)["']?([a-zA-Z0-9_.-]{8,})["']?/gi,
  SQL_QUERY: /SELECT.+FROM.+WHERE|INSERT INTO.+VALUES|UPDATE.+SET.+WHERE|DELETE FROM.+WHERE/gi,
  SQL_INJECTION: /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
  CREDENTIAL: /(?:password|passwd|pwd|secret)[=:]\s*["']?([a-zA-Z0-9!@#$%^&*()_+]{8,})["']?/gi,
  INTERNAL_DOMAIN: /(?:internal|corp|intranet|private)\.[\w-]+\.[a-z]{2,}/gi,
  SECRET_KEY: /(?:secret[_-]?key|private[_-]?key)[=:]\s*["']?([a-zA-Z0-9-_=+/]{16,})["']?/gi,
  PROPRIETARY_MARKER: /(?:confidential|proprietary|internal[_-]?use[_-]?only|do[_-]?not[_-]?share)/gi,
};

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
  Object.values(PATTERNS).forEach(pattern => pattern.lastIndex = 0);
  
  // Check for SSN
  let match: RegExpExecArray | null;
  while ((match = PATTERNS.SSN.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Social Security Numbers (SSN) are highly sensitive personal identifiers that should never be shared.'
    );
  }

  // Check for DOB
  while ((match = PATTERNS.DOB.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Dates of birth are sensitive personal information that could be used for identity theft.'
    );
  }

  // Check for API keys
  while ((match = PATTERNS.API_KEY.exec(text)) !== null) {
    addDetection(
      'api_key',
      match,
      'high',
      'API keys should never be shared with external services as they can grant access to your systems and data.'
    );
  }
  
  // Check for named API keys (like Google_API_key = xyz)
  while ((match = PATTERNS.NAMED_API_KEY.exec(text)) !== null) {
    addDetection(
      'api_key',
      match,
      'high',
      'Named API keys should never be shared as they can grant access to specific services and data.'
    );
  }
  
  // Check for SQL queries
  while ((match = PATTERNS.SQL_QUERY.exec(text)) !== null) {
    addDetection(
      'sql_query',
      match,
      'medium',
      'SQL queries may contain database schema information or expose internal data structures.'
    );
  }
  
  // Check for potential SQL injection patterns
  while ((match = PATTERNS.SQL_INJECTION.exec(text)) !== null) {
    addDetection(
      'sql_query',
      match,
      'high',
      'This SQL pattern may indicate an SQL injection vulnerability.'
    );
  }
  
  // Check for credentials
  while ((match = PATTERNS.CREDENTIAL.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Passwords and credentials should never be shared with external services.'
    );
  }
  
  // Check for internal domains
  while ((match = PATTERNS.INTERNAL_DOMAIN.exec(text)) !== null) {
    addDetection(
      'internal_domain',
      match,
      'medium',
      'Internal domain names can reveal details about your organization\'s infrastructure.'
    );
  }

  // Check for secret keys
  while ((match = PATTERNS.SECRET_KEY.exec(text)) !== null) {
    addDetection(
      'api_key',
      match,
      'high',
      'Secret keys provide access to sensitive systems and should be kept strictly private.'
    );
  }
  
  // Check for proprietary markers
  while ((match = PATTERNS.PROPRIETARY_MARKER.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'medium',
      'This appears to be marked as proprietary or confidential information.'
    );
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

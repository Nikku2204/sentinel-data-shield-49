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
  // Personal Identifiers
  SSN: /\b(?:\d{3}-\d{2}-\d{4}|\d{3}[.-]?\d{2}[.-]?\d{4})\b/g,
  // Updated Driver's License pattern to match formats like D123-456-7890
  DRIVERS_LICENSE: /\b(?:[A-Z]\d{7}|[A-Z]\d{3}-\d{3}-\d{4})\b/g,
  PASSPORT: /\b[A-Z]\d{8}\b/g,
  
  // Contact Information
  PHONE: /\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b/g,
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  ADDRESS: /\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Circle|Cir|Trail|Trl),?\s+[A-Za-z\s]+,?\s+[A-Z]{2}\b/gi,
  
  // Medical Information
  PATIENT_ID: /\b(?:Patient\s*ID|MRN)[-:]?\s*\d+\b/gi,
  DIAGNOSIS: /\bDiagnosis:\s*[A-Za-z\s]+(?:\s+(?:Type|Stage|Grade)\s+[IVX\d]+)?\b/gi,
  INSURANCE_ID: /\b(?:[A-Za-z]+\s*#\s*\d+)\b/g,
  PRESCRIPTION: /\b[A-Za-z]+\s+\d+(?:mg|ML|g)\b/gi,
  
  // Financial Information
  CREDIT_CARD: /\b(?:\d{4}[- ]?){4}\b/g,
  BANK_ACCOUNT: /\b(?:Account|Routing)\s*(?:Number|#)?\s*:?\s*\d{8,17}\b/gi,
  TIN: /\b\d{2}[-–]\d{7}\b/g,
  
  // Credentials and Keys
  API_KEY: /(?:api[_-]?key|access[_-]?token|secret|token|key)[=:]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
  NAMED_API_KEY: /\b\w+(?:[_-]?(?:api|key|token|secret))\s*[=:]\s*["']?[a-zA-Z0-9_.-]{8,}["']?/gi,
  PRIVATE_KEY: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[^-]*-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gs,
  PASSWORD: /\b(?:password|passwd|pwd)[=:]\s*["']?[A-Za-z\d!@#$%^&*()_+\-]{8,}["']?/gi,
  
  // Business Information
  CLIENT_LIST: /\bClient(?:\s+List)?:\s*(?:[A-Za-z]+(?:,\s*)?)+/gi,
  PROJECT_CODE: /\bProject\s+Code:\s*[A-Za-z0-9-]+\s*(?:-\s*(?:Top\s+Secret|Confidential))?\b/gi,
  NDA_CONTENT: /\b(?:NDA|Non-Disclosure)\s+(?:Agreement|Clause):[^.]+\b/gi,
  
  // Other Sensitive Data
  COORDINATES: /\b\d+\.\d+°\s*[NS],\s*\d+\.\d+°\s*[EW]\b/g,
  
  // Updated SSN pattern to match formats like 012-123-2044
  SSN: /\b(?:\d{3}-\d{2}-\d{4}|\d{3}[.-]?\d{2}[.-]?\d{4})\b/g,
  
  // Updated DOB pattern to match formats like 01/01/1999
  DOB: /\b(?:0?[1-9]|1[0-2])[\/.-](0?[1-9]|[12]\d|3[01])[\/.-](?:19|20)\d{2}\b/g,
  
  // Format like Google_API_key = 123n123hkasdf9195
  API_KEY: /(?:api[_-]?key|access[_-]?token|secret|token|key)[=:]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
  
  // Improved pattern for named API keys with more flexible format matching
  NAMED_API_KEY: /\b\w+(?:[_-]?(?:api|key|token|secret))\s*[=:]\s*["']?[a-zA-Z0-9_.-]{8,}["']?/gi,
  
  SQL_QUERY: /SELECT.+FROM.+WHERE|INSERT INTO.+VALUES|UPDATE.+SET.+WHERE|DELETE FROM.+WHERE/gi,
  SQL_INJECTION: /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
  
  // Enhanced credential pattern to match more formats
  CREDENTIAL: /(?:password|passwd|pwd|secret|ssn)[=:]\s*["']?([a-zA-Z0-9!@#$%^&*()_+\-]{4,})["']?/gi,
  
  INTERNAL_DOMAIN: /(?:internal|corp|intranet|private)\.[\w-]+\.[a-z]{2,}/gi,
  SECRET_KEY: /(?:secret[_-]?key|private[_-]?key)[=:]\s*["']?([a-zA-Z0-9-_=+/]{16,})["']?/gi,
  PROPRIETARY_MARKER: /(?:confidential|proprietary|internal[_-]?use[_-]?only|do[_-]?not[_-]?share)/gi,
  
  // Add patterns for labeled sensitive information
  LABELED_SSN: /\b(?:ssn|social\s*security(?:\s*number)?)\s*:?\s*\d{3}-?\d{2}-?\d{4}\b/gi,
  LABELED_DOB: /\b(?:dob|date\s*of\s*birth|birth\s*date)\s*:?\s*(?:0?[1-9]|1[0-2])[\/.-](?:0?[1-9]|[12]\d|3[01])[\/.-](?:19|20)\d{2}\b/gi,
  PATIENT_INFO: /\b(?:patient\s*info|patient\s*information|medical\s*record)\b/gi,
  
  // License number with format like "License No.: D123-456-7890"
  LICENSE_NO: /\b(?:License\s+No\.?|DL\s+Number):\s*[A-Z]\d{3}-\d{3}-\d{4}\b/gi,
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

  // Check for labeled SSN
  while ((match = PATTERNS.LABELED_SSN.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Labeled Social Security Numbers are highly sensitive personal identifiers that should never be shared.'
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
  
  // Check for labeled DOB
  while ((match = PATTERNS.LABELED_DOB.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Labeled dates of birth are sensitive personal information that could be used for identity theft.'
    );
  }

  // Check for patient information markers
  while ((match = PATTERNS.PATIENT_INFO.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'high',
      'Patient information is protected health data that should not be shared with external services.'
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
  
  // Check for driver's license
  while ((match = PATTERNS.DRIVERS_LICENSE.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Driver\'s license numbers are sensitive personal identifiers that should not be shared.'
    );
  }

  // Check for passport numbers
  while ((match = PATTERNS.PASSPORT.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Passport numbers are highly sensitive personal identifiers that should not be shared.'
    );
  }

  // Check for phone numbers
  while ((match = PATTERNS.PHONE.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'medium',
      'Phone numbers are personal contact information that should be handled carefully.'
    );
  }

  // Check for email addresses
  while ((match = PATTERNS.EMAIL.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'medium',
      'Email addresses are personal contact information that should be handled carefully.'
    );
  }

  // Check for addresses
  while ((match = PATTERNS.ADDRESS.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Physical addresses are sensitive personal information that should not be shared.'
    );
  }

  // Check for patient IDs and medical information
  while ((match = PATTERNS.PATIENT_ID.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'high',
      'Patient IDs are protected health information covered by privacy regulations.'
    );
  }

  // Check for diagnoses
  while ((match = PATTERNS.DIAGNOSIS.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'high',
      'Medical diagnoses are protected health information that should not be shared.'
    );
  }

  // Check for financial information
  while ((match = PATTERNS.CREDIT_CARD.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Credit card numbers should never be shared in plain text.'
    );
  }

  // Check for bank account information
  while ((match = PATTERNS.BANK_ACCOUNT.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Bank account information should never be shared in plain text.'
    );
  }

  // Check for private keys
  while ((match = PATTERNS.PRIVATE_KEY.exec(text)) !== null) {
    addDetection(
      'api_key',
      match,
      'high',
      'Private keys should never be shared and must be kept secure.'
    );
  }

  // Check for client lists
  while ((match = PATTERNS.CLIENT_LIST.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'medium',
      'Client lists are confidential business information.'
    );
  }

  // Check for project codes
  while ((match = PATTERNS.PROJECT_CODE.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'high',
      'Internal project codes and classifications should remain confidential.'
    );
  }

  // Check for NDA content
  while ((match = PATTERNS.NDA_CONTENT.exec(text)) !== null) {
    addDetection(
      'proprietary',
      match,
      'high',
      'NDA content is confidential and should not be shared.'
    );
  }
  
  // Check for License Number (new)
  while ((match = PATTERNS.LICENSE_NO.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Driver\'s license numbers are sensitive personal identifiers that should not be shared.'
    );
  }

  // Check for driver's license (updated to catch the new format)
  while ((match = PATTERNS.DRIVERS_LICENSE.exec(text)) !== null) {
    addDetection(
      'credential',
      match,
      'high',
      'Driver\'s license numbers are sensitive personal identifiers that should not be shared.'
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

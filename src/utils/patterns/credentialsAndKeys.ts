
import { PatternDefinition } from './types';

export const credentialsAndKeysPatterns: Record<string, PatternDefinition> = {
  API_KEY: {
    pattern: /(?:api[_-]?key|access[_-]?token|secret|token|key)[=:]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
    type: 'api_key',
    riskLevel: 'high',
    explanation: 'API keys should never be shared with external services as they can grant access to your systems and data.'
  },
  NAMED_API_KEY: {
    pattern: /\b\w+(?:[_-]?(?:api|key|token|secret))\s*[=:]\s*["']?[a-zA-Z0-9_.-]{8,}["']?/gi,
    type: 'api_key',
    riskLevel: 'high',
    explanation: 'Named API keys should never be shared as they can grant access to specific services and data.'
  },
  PRIVATE_KEY: {
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[^-]*-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gs,
    type: 'api_key',
    riskLevel: 'high',
    explanation: 'Private keys should never be shared and must be kept secure.'
  },
  SECRET_KEY: {
    pattern: /(?:secret[_-]?key|private[_-]?key)[=:]\s*["']?([a-zA-Z0-9-_=+/]{16,})["']?/gi,
    type: 'api_key',
    riskLevel: 'high',
    explanation: 'Secret keys provide access to sensitive systems and should be kept strictly private.'
  },
  PASSWORD: {
    pattern: /\b(?:password|passwd|pwd)[=:]\s*["']?[A-Za-z\d!@#$%^&*()_+\-]{8,}["']?/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Passwords and credentials should never be shared with external services.'
  },
  CREDENTIAL: {
    pattern: /(?:password|passwd|pwd|secret|ssn)[=:]\s*["']?([a-zA-Z0-9!@#$%^&*()_+\-]{4,})["']?/gi,
    type: 'credential',
    riskLevel: 'high',
    explanation: 'Passwords and credentials should never be shared with external services.'
  }
};

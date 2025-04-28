
import { PatternDefinition } from './types';

export const miscInformationPatterns: Record<string, PatternDefinition> = {
  COORDINATES: {
    pattern: /\b\d+\.\d+°\s*[NS],\s*\d+\.\d+°\s*[EW]\b/g,
    type: 'proprietary',
    riskLevel: 'medium',
    explanation: 'Geographical coordinates may reveal sensitive location information.'
  },
  SQL_QUERY: {
    pattern: /SELECT.+FROM.+WHERE|INSERT INTO.+VALUES|UPDATE.+SET.+WHERE|DELETE FROM.+WHERE/gi,
    type: 'sql_query',
    riskLevel: 'medium',
    explanation: 'SQL queries may contain database schema information or expose internal data structures.'
  },
  SQL_INJECTION: {
    pattern: /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
    type: 'sql_query',
    riskLevel: 'high',
    explanation: 'This SQL pattern may indicate an SQL injection vulnerability.'
  }
};

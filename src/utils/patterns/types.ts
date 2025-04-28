
export interface Detection {
  id: string;
  type: 'api_key' | 'sql_query' | 'credential' | 'internal_domain' | 'proprietary';
  content: string;
  startIndex: number;
  endIndex: number;
  riskLevel: 'high' | 'medium' | 'low';
  explanation: string;
}

export interface PatternDefinition {
  pattern: RegExp;
  type: Detection['type'];
  riskLevel: Detection['riskLevel'];
  explanation: string;
}

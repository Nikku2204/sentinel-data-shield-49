
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Shield, AlertTriangle, AlertCircle } from 'lucide-react';
import { Detection } from '@/utils/scanners';
import { cn } from '@/lib/utils';
import { generateSafeAlternatives } from '@/utils/sanitizers';

interface DetectionCardProps {
  detection: Detection;
}

const DetectionCard: React.FC<DetectionCardProps> = ({ detection }) => {
  const alternatives = generateSafeAlternatives(detection);
  
  const renderRiskBadge = () => {
    const config = {
      high: { color: 'bg-red-100 text-red-800 border-red-200', icon: AlertCircle },
      medium: { color: 'bg-yellow-100 text-yellow-800 border-yellow-200', icon: AlertTriangle },
      low: { color: 'bg-blue-100 text-blue-800 border-blue-200', icon: Shield }
    };
    
    const { color, icon: Icon } = config[detection.riskLevel];
    
    return (
      <Badge variant="outline" className={cn('ml-2 px-2 py-0.5', color)}>
        <Icon size={12} className="mr-1" />
        {detection.riskLevel.charAt(0).toUpperCase() + detection.riskLevel.slice(1)} Risk
      </Badge>
    );
  };
  
  const getTypeLabel = (type: Detection['type']): string => {
    const typeLabels: Record<Detection['type'], string> = {
      api_key: 'API Key / Secret',
      sql_query: 'SQL Query',
      credential: 'Credential',
      internal_domain: 'Internal Domain',
      proprietary: 'Proprietary Information'
    };
    
    return typeLabels[type];
  };

  return (
    <Card className="mb-4 card-hover border-l-4 border-l-red-500">
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center">
          <CardTitle className="text-base">{getTypeLabel(detection.type)}</CardTitle>
          {renderRiskBadge()}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <h4 className="text-sm font-medium mb-1">Detected content:</h4>
          <div className="bg-gray-50 p-2 rounded-sm border border-gray-200 font-mono text-sm overflow-x-auto">
            {detection.content}
          </div>
        </div>
        
        <div>
          <h4 className="text-sm font-medium mb-1">Risk explanation:</h4>
          <p className="text-sm text-gray-700">{detection.explanation}</p>
        </div>
        
        <div>
          <h4 className="text-sm font-medium mb-1">Safer alternatives:</h4>
          <ul className="list-disc pl-4">
            {alternatives.map((alt, idx) => (
              <li key={idx} className="text-sm text-gray-700 mb-1">{alt}</li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};

export default DetectionCard;

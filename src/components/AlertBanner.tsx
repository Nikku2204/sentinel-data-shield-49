
import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldX } from 'lucide-react';
import { cn } from '@/lib/utils';

interface AlertBannerProps {
  riskLevel: 'safe' | 'warning' | 'danger';
  detectionCount: number;
}

const AlertBanner: React.FC<AlertBannerProps> = ({ riskLevel, detectionCount }) => {
  const bannerConfig = {
    safe: {
      icon: ShieldCheck,
      bg: 'bg-green-50',
      border: 'border-green-200',
      text: 'text-green-800',
      title: 'Content appears safe to share',
      description: 'No sensitive information detected in your content.'
    },
    warning: {
      icon: AlertTriangle,
      bg: 'bg-yellow-50',
      border: 'border-yellow-200',
      text: 'text-yellow-800',
      title: 'Potential sensitive information detected',
      description: `${detectionCount} potential issue${detectionCount !== 1 ? 's' : ''} found that may need attention.`
    },
    danger: {
      icon: ShieldX,
      bg: 'bg-red-50',
      border: 'border-red-200',
      text: 'text-red-800',
      title: 'High-risk content detected',
      description: `${detectionCount} critical issue${detectionCount !== 1 ? 's' : ''} found that should be addressed before sharing.`
    }
  };

  const config = bannerConfig[riskLevel];
  const Icon = config.icon;
  
  return (
    <div className={cn(
      'flex items-start p-4 mb-6 rounded-md border',
      config.bg,
      config.border,
      config.text
    )}>
      <div className="mr-3 mt-0.5">
        <Icon size={20} className={cn(config.text)} />
      </div>
      <div>
        <h3 className="font-semibold mb-1">{config.title}</h3>
        <p className="text-sm">{config.description}</p>
      </div>
    </div>
  );
};

export default AlertBanner;

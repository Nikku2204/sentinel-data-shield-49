
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Shield, ShieldAlert } from "lucide-react";
import { scanForSensitiveData, analyzeRiskLevel, Detection } from '@/utils/scanners';
import { toast } from "@/hooks/use-toast";

interface ScannerInputProps {
  onScanComplete: (text: string, detections: Detection[], riskLevel: 'safe' | 'warning' | 'danger') => void;
}

const ScannerInput: React.FC<ScannerInputProps> = ({ onScanComplete }) => {
  const [text, setText] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);

  const handleScan = () => {
    if (!text.trim()) return;
    
    setIsScanning(true);
    
    // Simulate processing time for better UX
    setTimeout(() => {
      const detections = scanForSensitiveData(text);
      const riskLevel = analyzeRiskLevel(detections);
      
      onScanComplete(text, detections, riskLevel);
      
      // Show a toast message with the scan results
      if (detections.length > 0) {
        toast({
          title: `${detections.length} sensitive items detected`,
          description: `Risk level: ${riskLevel}`,
          variant: riskLevel === 'danger' ? 'destructive' : 'default'
        });
      }
      
      setIsScanning(false);
    }, 800);
  };

  return (
    <div className="w-full space-y-4">
      <div className="relative">
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste your content here to scan for sensitive data before sharing with external AI tools..."
          className="min-h-[200px] p-4 text-sm font-mono border-2 border-gray-200 focus:border-primary/60"
        />
        <div className="absolute bottom-4 right-4 text-gray-400 text-xs">
          {text.length} characters
        </div>
      </div>

      <Button 
        onClick={handleScan} 
        disabled={isScanning || !text.trim()}
        className="w-full py-6"
      >
        {isScanning ? (
          <>
            <div className="animate-spin mr-2">
              <ShieldAlert size={18} />
            </div>
            Scanning for sensitive data...
          </>
        ) : (
          <>
            <Shield size={18} className="mr-2" />
            Scan for Sensitive Content
          </>
        )}
      </Button>
    </div>
  );
};

export default ScannerInput;

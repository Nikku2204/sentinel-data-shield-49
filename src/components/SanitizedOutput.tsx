
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Check, Copy, RotateCw } from 'lucide-react';
import { sanitizeText } from '@/utils/sanitizers';
import { Detection } from '@/utils/scanners';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/ui/use-toast';

interface SanitizedOutputProps {
  originalText: string;
  detections: Detection[];
}

const SanitizedOutput: React.FC<SanitizedOutputProps> = ({ originalText, detections }) => {
  const [sanitizedText, setSanitizedText] = useState<string>(sanitizeText(originalText, detections));
  const [copied, setCopied] = useState<boolean>(false);
  const { toast } = useToast();

  const handleCopy = () => {
    navigator.clipboard.writeText(sanitizedText).then(() => {
      setCopied(true);
      toast({
        title: "Copied to clipboard",
        description: "Sanitized content has been copied to your clipboard.",
      });
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleResanitize = () => {
    setSanitizedText(sanitizeText(originalText, detections));
    toast({
      title: "Content re-sanitized",
      description: "The content has been sanitized again with current detection rules.",
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Sanitized Version</h3>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm"
            onClick={handleResanitize}
            className="flex items-center"
          >
            <RotateCw size={14} className="mr-1" />
            Re-sanitize
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleCopy}
            className={cn("flex items-center", copied ? "bg-green-50 text-green-700" : "")}
          >
            {copied ? (
              <>
                <Check size={14} className="mr-1" />
                Copied
              </>
            ) : (
              <>
                <Copy size={14} className="mr-1" />
                Copy
              </>
            )}
          </Button>
        </div>
      </div>

      <div className="relative">
        <div className="min-h-[150px] max-h-[300px] bg-gray-50 font-mono text-sm p-4 rounded-md border border-gray-200 overflow-auto whitespace-pre-wrap">
          {sanitizedText || 'No content to sanitize.'}
        </div>
      </div>

      {detections.length > 0 && (
        <p className="text-xs text-gray-500 italic">
          {detections.length} {detections.length === 1 ? 'item' : 'items'} sanitized.
          Use this version when sharing with external AI tools.
        </p>
      )}
    </div>
  );
};

export default SanitizedOutput;

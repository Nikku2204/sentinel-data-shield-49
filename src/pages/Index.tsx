import React, { useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Shield, ShieldAlert } from 'lucide-react';
import { Detection } from '@/utils/scanners';
import ScannerInput from '@/components/ScannerInput';
import AlertBanner from '@/components/AlertBanner';
import DetectionCard from '@/components/DetectionCard';
import SanitizedOutput from '@/components/SanitizedOutput';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Scan } from 'lucide-react';

const Index = () => {
  const [originalText, setOriginalText] = useState<string>('');
  const [detections, setDetections] = useState<Detection[]>([]);
  const [riskLevel, setRiskLevel] = useState<'safe' | 'warning' | 'danger'>('safe');
  const [showResults, setShowResults] = useState<boolean>(false);

  const handleScanComplete = (
    text: string,
    detections: Detection[],
    riskLevel: 'safe' | 'warning' | 'danger'
  ) => {
    setOriginalText(text);
    setDetections(detections);
    setRiskLevel(riskLevel);
    setShowResults(true);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50/80 to-slate-50 dark:from-gray-900 dark:to-gray-800">
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200 shadow-sm dark:bg-gray-900/80 dark:border-gray-800">
        <div className="container mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <ShieldAlert className="text-primary h-8 w-8 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">shareSafe</h1>
                <p className="text-sm text-gray-600 dark:text-gray-400">Protect sensitive data from AI exposure</p>
              </div>
            </div>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto py-10 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          {!showResults ? (
            <Card className="mb-8 overflow-hidden border-gray-200/60 shadow-lg">
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950 py-6 px-6">
                <h2 className="text-2xl font-semibold mb-2">Protect Your Sensitive Data</h2>
                <p className="text-gray-600 dark:text-gray-400">
                  Scan content before sharing with external AI tools to prevent accidental data leaks
                </p>
              </div>
              <CardContent className="pt-6">
                <ScannerInput onScanComplete={handleScanComplete} />
              </CardContent>
            </Card>
          ) : (
            <>
              <AlertBanner riskLevel={riskLevel} detectionCount={detections.length} />
              
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2">
                  {detections.length > 0 ? (
                    <div className="mb-6">
                      <div className="flex items-center justify-between mb-4">
                        <h2 className="text-xl font-semibold flex items-center">
                          <ShieldAlert size={20} className="mr-2 text-red-500" />
                          Detections ({detections.length})
                        </h2>
                      </div>
                      <div className="space-y-4">
                        {detections.map(detection => (
                          <DetectionCard 
                            key={detection.id} 
                            detection={detection} 
                          />
                        ))}
                      </div>
                    </div>
                  ) : (
                    <Card className="mb-6 overflow-hidden border-gray-200/60 shadow-md">
                      <CardContent className="pt-6">
                        <div className="flex items-center justify-center py-12 text-center">
                          <div>
                            <Shield size={56} className="mx-auto mb-5 text-green-500 p-2 bg-green-50 rounded-full" />
                            <h3 className="text-xl font-medium mb-3">No sensitive content detected</h3>
                            <p className="text-gray-500 max-w-sm mx-auto">
                              Your content appears safe to share with external AI tools.
                            </p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
                
                <div className="lg:col-span-1">
                  <Card className="border-gray-200/60 shadow-md">
                    <CardContent className="pt-6">
                      {detections.length > 0 ? (
                        <SanitizedOutput
                          originalText={originalText}
                          detections={detections}
                        />
                      ) : (
                        <div>
                          <h3 className="text-lg font-semibold mb-3">Your Content</h3>
                          <div className="max-h-[300px] bg-gray-50 dark:bg-gray-900 font-mono text-sm p-4 rounded-md border border-gray-200 dark:border-gray-700 overflow-auto whitespace-pre-wrap">
                            {originalText}
                          </div>
                          <p className="text-xs text-gray-500 italic mt-3">
                            No sanitization needed. Content is safe to share.
                          </p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>
              </div>
              
              <div className="mt-8 text-center">
                <button 
                  onClick={() => setShowResults(false)} 
                  className="
                    flex items-center justify-center 
                    mx-auto 
                    px-6 py-3 
                    bg-primary 
                    text-white 
                    rounded-lg 
                    shadow-md 
                    hover:bg-primary/90 
                    transition-colors 
                    duration-300 
                    group
                  "
                >
                  <Scan className="mr-2 size-5 group-hover:animate-pulse" />
                  Scan New Content
                </button>
              </div>
            </>
          )}
        </div>
      </main>
      
      <footer className="bg-white/80 backdrop-blur-sm border-t border-gray-200 mt-12 dark:bg-gray-900/80 dark:border-gray-800">
        <div className="container mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <p className="text-sm text-center text-gray-500 dark:text-gray-400">
            Sentinel Data Shield - Protecting your sensitive information from AI exposure
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;


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
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-slate-50">
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="container mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <ShieldAlert className="text-primary h-8 w-8 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Sentinel Data Shield</h1>
                <p className="text-sm text-gray-600">Protect sensitive data from AI exposure</p>
              </div>
            </div>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          {!showResults ? (
            <Card className="mb-8">
              <CardContent className="pt-6">
                <div className="mb-6">
                  <h2 className="text-xl font-semibold mb-2">Scan Your Content</h2>
                  <p className="text-gray-600">
                    Detect sensitive information before sharing with external AI tools like ChatGPT to prevent accidental data leaks.
                  </p>
                </div>
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
                      <div>
                        {detections.map(detection => (
                          <DetectionCard 
                            key={detection.id} 
                            detection={detection} 
                          />
                        ))}
                      </div>
                    </div>
                  ) : (
                    <Card className="mb-6">
                      <CardContent className="pt-6">
                        <div className="flex items-center justify-center py-8 text-center">
                          <div>
                            <Shield size={48} className="mx-auto mb-4 text-green-500" />
                            <h3 className="text-xl font-medium mb-2">No sensitive content detected</h3>
                            <p className="text-gray-500">
                              Your content appears safe to share with external AI tools.
                            </p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
                
                <div className="lg:col-span-1">
                  <Card>
                    <CardContent className="pt-6">
                      {detections.length > 0 ? (
                        <SanitizedOutput
                          originalText={originalText}
                          detections={detections}
                        />
                      ) : (
                        <div>
                          <h3 className="text-lg font-semibold mb-3">Your Content</h3>
                          <div className="max-h-[300px] bg-gray-50 font-mono text-sm p-4 rounded-md border border-gray-200 overflow-auto whitespace-pre-wrap">
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
              
              <div className="mt-6 text-center">
                <button 
                  onClick={() => setShowResults(false)} 
                  className="text-primary hover:underline text-sm"
                >
                  Scan new content
                </button>
              </div>
            </>
          )}
        </div>
      </main>
      
      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="container mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <p className="text-sm text-center text-gray-500">
            Sentinel Data Shield - Protecting your sensitive information from AI exposure
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;

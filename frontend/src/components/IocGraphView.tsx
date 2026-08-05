import React, { useState } from 'react';

interface GraphNode {
  id: string;
  label: string;
  type: 'Email' | 'Attachment' | 'URL' | 'IP' | 'Domain';
  riskScore: number;
  details: string;
}

export const IocGraphView: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const nodes: GraphNode[] = [
    { id: '1', label: 'invoice_urgent.eml', type: 'Email', riskScore: 0.94, details: 'Phishing email impersonating Accounts Payable' },
    { id: '2', label: 'remittance_pdf.exe', type: 'Attachment', riskScore: 0.98, details: 'ClamAV matched Win32.Trojan.Agent.X2' },
    { id: '3', label: 'http://account-verify-sec.com/login', type: 'URL', riskScore: 0.91, details: 'VirusTotal 18/65 malicious detections' },
    { id: '4', label: '185.220.101.5', type: 'IP', riskScore: 0.88, details: 'AbuseIPDB high confidence malicious exit node' },
    { id: '5', label: 'c2.malicious-domain.cc', type: 'Domain', riskScore: 0.95, details: 'AlienVault OTX active C2 infrastructure' },
  ];

  return (
    <div className="space-y-4 glass-panel p-6">
      <div className="flex justify-between items-center border-b border-slate-800 pb-3">
        <div>
          <h3 className="font-bold text-white text-base flex items-center space-x-2">
            <span>🕸️</span>
            <span>IOC Threat Relationship Pivot Graph</span>
          </h3>
          <p className="text-xs text-slate-400">Interactive link graph mapping threat vectors and infrastructure</p>
        </div>
        <div className="flex items-center space-x-2 text-[10px] font-mono">
          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">Critical IOC</span>
          <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40">High Risk</span>
        </div>
      </div>

      {/* Visual Graph View */}
      <div className="relative min-h-[220px] bg-slate-950/80 rounded-xl border border-slate-800/80 p-6 flex flex-wrap items-center justify-around gap-4">
        {nodes.map((node) => (
          <button
            key={node.id}
            onClick={() => setSelectedNode(node)}
            className={`p-3.5 rounded-2xl border text-left transition-all hover:scale-105 focus-visible:ring-2 focus-visible:ring-blue-500 ${
              selectedNode?.id === node.id ? 'ring-2 ring-cyan-400 border-cyan-400' : ''
            } ${
              node.riskScore >= 0.9
                ? 'bg-rose-500/10 border-rose-500/40 text-rose-200'
                : 'bg-amber-500/10 border-amber-500/40 text-amber-200'
            }`}
          >
            <div className="flex justify-between items-center space-x-3 text-[10px] font-mono">
              <span className="px-1.5 py-0.2 rounded bg-slate-900 text-cyan-400 border border-slate-800 font-bold">
                {node.type}
              </span>
              <span className="font-bold text-rose-400">{(node.riskScore * 100).toFixed(0)}%</span>
            </div>
            <div className="text-xs font-mono font-bold text-white mt-1.5 max-w-[180px] truncate">{node.label}</div>
          </button>
        ))}
      </div>

      {/* Selected Graph Node Details */}
      {selectedNode && (
        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 text-xs space-y-2 animate-fade-in font-mono">
          <div className="flex justify-between items-center">
            <span className="font-bold text-slate-200">Selected Node: {selectedNode.label}</span>
            <span className="text-rose-400 font-bold">Risk Score: {(selectedNode.riskScore * 100).toFixed(0)}%</span>
          </div>
          <div className="text-slate-400 font-sans">{selectedNode.details}</div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  detectedCount: number;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
}

export const MitreMatrix: React.FC = () => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const tactics = [
    {
      name: 'Initial Access',
      techniques: [
        { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', detectedCount: 14, description: 'Spearphishing attachments & links in email', severity: 'Critical' },
        { id: 'T1190', name: 'Exploit Public App', tactic: 'Initial Access', detectedCount: 2, description: 'Exploiting software vulnerabilities in web edge', severity: 'Medium' },
      ],
    },
    {
      name: 'Execution',
      techniques: [
        { id: 'T1204', name: 'User Execution', tactic: 'Execution', detectedCount: 9, description: 'User opening malicious attachment or link', severity: 'High' },
        { id: 'T1059', name: 'Command & Scripting', tactic: 'Execution', detectedCount: 5, description: 'PowerShell / VBScript execution via document macro', severity: 'High' },
      ],
    },
    {
      name: 'Defense Evasion',
      techniques: [
        { id: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion', detectedCount: 7, description: 'Base64 / XOR obfuscated payloads in attachments', severity: 'High' },
        { id: 'T1221', name: 'Template Injection', tactic: 'Defense Evasion', detectedCount: 3, description: 'Remote template injection in docx files', severity: 'Medium' },
      ],
    },
    {
      name: 'Credential Access',
      techniques: [
        { id: 'T1556', name: 'Modify Auth Process', tactic: 'Credential Access', detectedCount: 4, description: 'Fake O365 / Microsoft login portals', severity: 'Critical' },
        { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', detectedCount: 1, description: 'Password spraying against web endpoints', severity: 'Low' },
      ],
    },
    {
      name: 'Command & Control',
      techniques: [
        { id: 'T1071', name: 'App Layer Protocol', tactic: 'Command & Control', detectedCount: 8, description: 'C2 beaconing over HTTP/HTTPS to malicious domains', severity: 'High' },
        { id: 'T1568', name: 'Dynamic Resolution', tactic: 'Command & Control', detectedCount: 3, description: 'Fast-flux DNS / Domain Generation Algorithms (DGA)', severity: 'Medium' },
      ],
    },
    {
      name: 'Exfiltration',
      techniques: [
        { id: 'T1048', name: 'Exfiltration Over Web', tactic: 'Exfiltration', detectedCount: 2, description: 'Data exfiltration over encrypted web sessions', severity: 'High' },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h3 className="font-bold text-lg text-white flex items-center space-x-2">
            <span>🛡️</span>
            <span>MITRE ATT&CK® Threat Matrix Navigator</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Real-time adversary tactics & technique mapping detected by CyberShield-AI-SOC models.
          </p>
        </div>
        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
            <span className="text-slate-300">Critical</span>
          </span>
          <span className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
            <span className="text-slate-300">High</span>
          </span>
          <span className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-blue-500" />
            <span className="text-slate-300">Medium</span>
          </span>
        </div>
      </div>

      {/* MITRE Matrix Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3 overflow-x-auto">
        {tactics.map((tac) => (
          <div key={tac.name} className="space-y-2">
            <div className="p-2.5 bg-slate-900/90 rounded-xl border border-slate-800 text-center">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-cyan-400 block">
                {tac.name}
              </span>
            </div>

            <div className="space-y-2">
              {tac.techniques.map((tech) => (
                <button
                  key={tech.id}
                  onClick={() => setSelectedTechnique(tech as MitreTechnique)}
                  className={`w-full p-3 rounded-xl border text-left transition-all hover:scale-[1.02] focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    tech.severity === 'Critical'
                      ? 'bg-rose-500/10 border-rose-500/30 text-rose-200 hover:border-rose-500/60'
                      : tech.severity === 'High'
                      ? 'bg-amber-500/10 border-amber-500/30 text-amber-200 hover:border-amber-500/60'
                      : 'bg-blue-500/10 border-blue-500/30 text-blue-200 hover:border-blue-500/60'
                  }`}
                >
                  <div className="flex justify-between items-center text-[10px] font-mono">
                    <span className="font-bold text-slate-400">{tech.id}</span>
                    <span className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 border border-slate-800 font-bold">
                      {tech.detectedCount} hits
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-white mt-1 leading-snug">{tech.name}</div>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Technique Detail Card */}
      {selectedTechnique && (
        <div className="glass-panel p-5 space-y-3 border-blue-500/40 animate-fade-in">
          <div className="flex justify-between items-center border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2">
              <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                {selectedTechnique.id}
              </span>
              <h4 className="font-bold text-white text-sm">{selectedTechnique.name}</h4>
            </div>
            <button
              onClick={() => setSelectedTechnique(null)}
              className="text-slate-400 hover:text-white text-xs"
            >
              ✕ Close Detail
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <span className="text-slate-400 block font-mono">Tactic Domain:</span>
              <span className="text-slate-200 font-medium">{selectedTechnique.tactic}</span>
            </div>
            <div>
              <span className="text-slate-400 block font-mono">Detection Count:</span>
              <span className="text-cyan-400 font-bold font-mono">{selectedTechnique.detectedCount} incidents</span>
            </div>
            <div>
              <span className="text-slate-400 block font-mono">Mapped Severity:</span>
              <span className="text-rose-400 font-bold font-mono">{selectedTechnique.severity}</span>
            </div>
            <div className="col-span-3 pt-2 border-t border-slate-800">
              <span className="text-slate-400 block font-mono">Technique Summary:</span>
              <p className="text-slate-300 mt-1 leading-relaxed">{selectedTechnique.description}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

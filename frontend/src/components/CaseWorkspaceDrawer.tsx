import React, { useState } from 'react';

interface CaseWorkspaceDrawerProps {
  caseDetail: any;
  onClose: () => void;
  newNoteContent: string;
  setNewNoteContent: (val: string) => void;
  onAddNote: (e: React.FormEvent) => void;
  onPivotIOC?: (ioc: string) => void;
}

export const CaseWorkspaceDrawer: React.FC<CaseWorkspaceDrawerProps> = ({
  caseDetail,
  onClose,
  newNoteContent,
  setNewNoteContent,
  onAddNote,
  onPivotIOC,
}) => {
  const [assignedAnalyst, setAssignedAnalyst] = useState('analyst@cybershield.io');
  const [caseSeverity, setCaseSeverity] = useState(caseDetail?.severity || 'High');

  if (!caseDetail) return null;

  const sampleEvidence = [
    { id: 'ev-1', name: 'suspicious_invoice_attachment.eml', type: 'EML Payload', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { id: 'ev-2', name: 'http://account-verify-sec.com/login', type: 'Malicious URL', hash: 'http_uri' },
    { id: 'ev-3', name: '185.220.101.5', type: 'C2 Exit IP', hash: 'ipv4_address' },
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/75 backdrop-blur-md flex justify-end animate-fade-in">
      <div className="w-full max-w-3xl bg-[#0b1120] border-l border-slate-800 shadow-2xl h-full flex flex-col justify-between animate-drawer overflow-y-auto">
        {/* Drawer Header */}
        <div>
          <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/80 sticky top-0 backdrop-blur z-20">
            <div>
              <div className="flex items-center space-x-3">
                <span className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded-md ${
                  caseSeverity === 'Critical' ? 'badge-critical' : caseSeverity === 'High' ? 'badge-high' : 'badge-medium'
                }`}>
                  {caseSeverity} SEVERITY
                </span>
                <span className="px-2.5 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {caseDetail.status || 'OPEN_INVESTIGATION'}
                </span>
              </div>
              <h2 className="text-xl font-bold text-white mt-2">{caseDetail.title}</h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition"
              aria-label="Close Case Workspace"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Drawer Body */}
          <div className="p-6 space-y-6">
            {/* Case Controls & Assigned Analyst */}
            <div className="glass-panel p-5 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Assigned SOC Analyst</label>
                <select
                  value={assignedAnalyst}
                  onChange={(e) => setAssignedAnalyst(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-blue-500 font-mono"
                >
                  <option value="analyst@cybershield.io">Analyst_L2 (analyst@cybershield.io)</option>
                  <option value="admin@cybershield.io">Admin (admin@cybershield.io)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Adjust Incident Severity</label>
                <select
                  value={caseSeverity}
                  onChange={(e) => setCaseSeverity(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-blue-500 font-mono"
                >
                  <option value="Critical">Critical Severity</option>
                  <option value="High">High Severity</option>
                  <option value="Medium">Medium Severity</option>
                  <option value="Low">Low Severity</option>
                </select>
              </div>
            </div>

            {/* Description */}
            <div className="glass-panel p-5 space-y-2 text-xs">
              <span className="text-slate-400 font-semibold uppercase tracking-wider block">Incident Scope & Description</span>
              <p className="text-slate-200 text-sm leading-relaxed">{caseDetail.description || 'Targeted email spearphishing campaign attempting to harvest M365 organization credentials.'}</p>
            </div>

            {/* Evidence & Artifact Gallery */}
            <div className="glass-panel p-5 space-y-3">
              <h4 className="font-bold text-slate-200 text-sm flex items-center space-x-2">
                <span>📁</span>
                <span>Associated Incident Evidence & Artifacts</span>
              </h4>
              <div className="space-y-2">
                {sampleEvidence.map((ev) => (
                  <div key={ev.id} className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 flex items-center justify-between text-xs font-mono">
                    <div>
                      <div className="text-slate-200 font-bold">{ev.name}</div>
                      <div className="text-[10px] text-slate-500">{ev.type} • {ev.hash.slice(0, 16)}...</div>
                    </div>
                    <button
                      onClick={() => onPivotIOC && onPivotIOC(ev.name)}
                      className="px-2.5 py-1 rounded bg-blue-500/10 text-cyan-400 border border-blue-500/30 hover:bg-blue-500/20 text-[11px]"
                    >
                      Pivot Indicator
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Analyst Notes Section */}
            <div className="glass-panel p-5 space-y-4">
              <h4 className="font-bold text-slate-200 text-sm flex items-center space-x-2">
                <span>💬</span>
                <span>Analyst Notes & Activity Annotations</span>
              </h4>

              <div className="space-y-3 max-h-56 overflow-y-auto pr-1">
                {caseDetail.notes && caseDetail.notes.length > 0 ? (
                  caseDetail.notes.map((n: any) => (
                    <div key={n.id} className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 text-xs space-y-1">
                      <div className="text-slate-200">{n.content}</div>
                      <div className="flex justify-between items-center text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800/50">
                        <span>Author: {assignedAnalyst}</span>
                        <span>{n.created_at}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-500 text-center py-4">No analyst notes recorded for this case.</div>
                )}
              </div>

              {/* Add Note Form */}
              <form onSubmit={onAddNote} className="flex items-center space-x-2 pt-2 border-t border-slate-800">
                <input
                  type="text"
                  placeholder="Add an investigation note..."
                  required
                  value={newNoteContent}
                  onChange={(e) => setNewNoteContent(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-xl transition"
                >
                  Post Note
                </button>
              </form>
            </div>

            {/* Incident Timeline Audit Trail */}
            <div className="glass-panel p-5 space-y-3">
              <h4 className="font-bold text-slate-200 text-sm flex items-center space-x-2">
                <span>⏱️</span>
                <span>Incident Timeline & Audit Trail</span>
              </h4>
              <div className="space-y-3 max-h-48 overflow-y-auto font-mono text-xs pl-2">
                {caseDetail.timeline && caseDetail.timeline.length > 0 ? (
                  caseDetail.timeline.map((ev: any) => (
                    <div key={ev.id} className="relative pl-6 pb-2 border-l-2 border-blue-500/40">
                      <div className="absolute -left-[5px] top-1.5 h-2 w-2 rounded-full bg-blue-400" />
                      <div className="text-slate-300 font-semibold">{ev.event_type}</div>
                      <div className="text-slate-400 text-[11px]">{ev.description}</div>
                      <div className="text-[10px] text-slate-500">{ev.timestamp}</div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs font-sans text-slate-500 text-center py-2">No timeline events logged.</div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Footer Close */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/95 backdrop-blur flex justify-end sticky bottom-0 z-20">
          <button
            onClick={onClose}
            className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold border border-slate-700 transition"
          >
            Close Case Workspace
          </button>
        </div>
      </div>
    </div>
  );
};

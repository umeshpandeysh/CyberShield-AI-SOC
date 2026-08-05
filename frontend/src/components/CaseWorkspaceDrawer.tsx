import React from 'react';

interface CaseWorkspaceDrawerProps {
  caseDetail: any;
  onClose: () => void;
  newNoteContent: string;
  setNewNoteContent: (val: string) => void;
  onAddNote: (e: React.FormEvent) => void;
}

export const CaseWorkspaceDrawer: React.FC<CaseWorkspaceDrawerProps> = ({
  caseDetail,
  onClose,
  newNoteContent,
  setNewNoteContent,
  onAddNote,
}) => {
  if (!caseDetail) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-md flex justify-end animate-fade-in">
      <div className="w-full max-w-3xl bg-[#0f172a] border-l border-slate-800 shadow-2xl h-full flex flex-col justify-between animate-drawer overflow-y-auto">
        {/* Drawer Header */}
        <div>
          <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/60 sticky top-0 backdrop-blur z-10">
            <div>
              <div className="flex items-center space-x-3">
                <span className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded-md ${
                  caseDetail.severity === 'Critical' ? 'badge-critical' : caseDetail.severity === 'High' ? 'badge-high' : 'badge-medium'
                }`}>
                  {caseDetail.severity} SEVERITY
                </span>
                <span className="px-2.5 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {caseDetail.status}
                </span>
              </div>
              <h2 className="text-xl font-bold text-white mt-2">{caseDetail.title}</h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Drawer Body */}
          <div className="p-6 space-y-6">
            {/* Description */}
            <div className="glass-panel p-5 space-y-2 text-xs">
              <span className="text-slate-400 font-semibold uppercase tracking-wider block">Incident Description</span>
              <p className="text-slate-200 text-sm leading-relaxed">{caseDetail.description || 'No description provided.'}</p>
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
                        <span>Author ID: {n.author_id ? n.author_id.slice(0, 8) : 'System'}</span>
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
                <span>Incident Timeline & Audit Events</span>
              </h4>
              <div className="space-y-3 max-h-48 overflow-y-auto font-mono text-xs pl-2">
                {caseDetail.timeline && caseDetail.timeline.length > 0 ? (
                  caseDetail.timeline.map((ev: any) => (
                    <div key={ev.id} className="relative pl-6 pb-2 border-l-2 border-blue-500/40">
                      <div className="absolute -left-[5px] top-1.5 h-2 w-2 rounded-full bg-blue-400" />
                      <div className="text-slate-300 font-medium">{ev.event_type}</div>
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
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 backdrop-blur flex justify-end sticky bottom-0">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold border border-slate-700"
          >
            Close Case Workspace
          </button>
        </div>
      </div>
    </div>
  );
};

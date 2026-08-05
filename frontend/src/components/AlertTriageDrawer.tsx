import React from 'react';

interface AlertTriageDrawerProps {
  alert: any;
  onClose: () => void;
  triageComment: string;
  setTriageComment: (val: string) => void;
  onTriage: (status: string) => void;
}

export const AlertTriageDrawer: React.FC<AlertTriageDrawerProps> = ({
  alert,
  onClose,
  triageComment,
  setTriageComment,
  onTriage,
}) => {
  if (!alert) return null;

  const riskPercent = Math.round((alert.risk_score || 0) * 100);

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-md flex justify-end animate-fade-in">
      <div className="w-full max-w-2xl bg-[#0f172a] border-l border-slate-800 shadow-2xl h-full flex flex-col justify-between animate-drawer overflow-y-auto">
        {/* Drawer Header */}
        <div>
          <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/60 sticky top-0 backdrop-blur z-10">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono text-slate-400">ALERT ID: {alert.id}</span>
                <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {alert.status}
                </span>
              </div>
              <h2 className="text-lg font-bold text-white mt-1">Threat Alert Deep Inspection & Triage</h2>
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
            {/* Risk Gauge Bar */}
            <div className="glass-panel p-5 space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Calculated Risk Score</span>
                <span className={`text-2xl font-extrabold font-mono ${riskPercent >= 80 ? 'text-rose-400' : riskPercent >= 50 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {riskPercent}%
                </span>
              </div>
              <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-500 ${
                    riskPercent >= 80
                      ? 'bg-gradient-to-r from-amber-500 to-rose-500'
                      : riskPercent >= 50
                      ? 'bg-gradient-to-r from-emerald-500 to-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${riskPercent}%` }}
                />
              </div>
            </div>

            {/* Email Metadata */}
            <div className="glass-panel p-5 space-y-3 text-xs">
              <h4 className="font-bold text-slate-200 text-sm border-b border-slate-800 pb-2">Email Specifications</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
                <div>
                  <span className="text-slate-500 block">Sender:</span>
                  <span className="text-slate-200 break-all">{alert.email?.sender || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Recipient:</span>
                  <span className="text-slate-200 break-all">{alert.email?.recipient || 'N/A'}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500 block">Subject:</span>
                  <span className="text-slate-200 font-sans text-sm font-medium">{alert.email?.subject || '(No Subject)'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Received At:</span>
                  <span className="text-slate-400">{alert.email?.received_at || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Message-ID:</span>
                  <span className="text-slate-400 break-all">{alert.email?.message_id || 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Explainable AI (XAI) Breakdown */}
            {alert.ai_explanation && (
              <div className="glass-panel p-5 space-y-3 border-blue-500/30">
                <div className="flex items-center space-x-2 text-blue-400 font-bold text-sm">
                  <span>🧠</span>
                  <span>Explainable AI (XAI) Inference Tokens</span>
                </div>
                <p className="text-xs text-slate-400">
                  Model confidence: <strong className="text-slate-200 font-mono">{((alert.ai_phishing_probability || 0) * 100).toFixed(1)}%</strong>
                </p>
                {alert.ai_explanation.critical_tokens?.length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-[11px] text-slate-400 font-semibold uppercase">Flagged Feature Tokens:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {alert.ai_explanation.critical_tokens.map((tok: string, idx: number) => (
                        <span key={idx} className="px-2 py-0.5 text-xs font-mono rounded-md bg-rose-500/10 text-rose-300 border border-rose-500/30">
                          {tok}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Drawer Footer Actions */}
        <div className="p-6 border-t border-slate-800 bg-slate-900/90 backdrop-blur space-y-3 sticky bottom-0">
          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider">Triage Analyst Notes</label>
          <input
            type="text"
            placeholder="Add triage investigation comments..."
            value={triageComment}
            onChange={(e) => setTriageComment(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <div className="flex space-x-3 pt-1">
            <button
              onClick={() => onTriage('RESOLVED_QUARANTINED')}
              className="flex-1 py-2.5 bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white text-xs font-bold rounded-xl shadow-lg shadow-rose-500/20 transition"
            >
              Quarantine & Contain Email
            </button>
            <button
              onClick={() => onTriage('RESOLVED_FALSE_POSITIVE')}
              className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-semibold rounded-xl border border-slate-700 transition"
            >
              Mark as False Positive
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

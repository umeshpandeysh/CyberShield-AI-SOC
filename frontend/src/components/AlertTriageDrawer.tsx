import React, { useState } from 'react';

interface AlertTriageDrawerProps {
  alert: any;
  onClose: () => void;
  triageComment: string;
  setTriageComment: (val: string) => void;
  onTriage: (status: string) => void;
  onPivotIOC?: (ioc: string) => void;
}

export const AlertTriageDrawer: React.FC<AlertTriageDrawerProps> = ({
  alert,
  onClose,
  triageComment,
  setTriageComment,
  onTriage,
  onPivotIOC,
}) => {
  const [activeTab, setActiveTab] = useState<'email' | 'xai' | 'yara' | 'headers'>('email');
  const [copiedText, setCopiedText] = useState('');

  if (!alert) return null;

  const riskPercent = Math.round((alert.risk_score || 0.85) * 100);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(''), 2000);
  };

  const sampleEmailBody = alert.email?.body || `Dear Executive,\n\nOur security system detected an unauthorized login attempt from IP 185.220.101.5 to your Microsoft 365 Tenant account. Please verify your credentials immediately by opening the attached remittance report or clicking the authentication portal below:\n\nhttp://account-verify-sec.com/login?session_id=98a76d5e\n\nFailure to verify within 24 hours will result in permanent account suspension.\n\nBest Regards,\nIT Security Helpdesk`;

  const sampleHeaders = `Received: from mail-ed1-f67.google.com (mail-ed1-f67.google.com [209.85.217.67])\n    by mx.cybershield.io with ESMTPS id q187si3948501edf.24.2026.08.04.14.22.10\n    for <analyst@cybershield.io>;\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com;\nX-Authentication-Results: spf=fail (sender IP 185.220.101.5); dkim=pass; dmarc=fail;\nMessage-ID: <20260804142210.39482.q187@suspicious-domain.net>\nUser-Agent: Thunderbird 115.3.1\nContent-Type: multipart/mixed; boundary="----=_Part_3892_10485.1691158930"`;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/75 backdrop-blur-md flex justify-end animate-fade-in">
      <div className="w-full max-w-3xl bg-[#0b1120] border-l border-slate-800 shadow-2xl h-full flex flex-col justify-between animate-drawer overflow-y-auto">
        {/* Drawer Header */}
        <div>
          <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/80 sticky top-0 backdrop-blur z-20">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono text-slate-400">ALERT ID: {alert.id}</span>
                <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                  alert.status === 'OPEN' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-slate-800 text-slate-300'
                }`}>
                  {alert.status}
                </span>
                <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  CRITICAL SEVERITY
                </span>
              </div>
              <h2 className="text-lg font-bold text-white mt-1.5 leading-snug">
                {alert.email?.subject || 'Urgent: Verify Microsoft 365 Account Credentials'}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition"
              aria-label="Close Alert Drawer"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Tab Navigation */}
          <div className="bg-slate-900/50 border-b border-slate-800 px-6 flex space-x-2 pt-2">
            {[
              { id: 'email', label: '✉️ Email & Payload' },
              { id: 'xai', label: '🧠 Explainable AI' },
              { id: 'yara', label: '🛡️ ClamAV & YARA' },
              { id: 'headers', label: '📋 MIME Headers' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-4 py-2.5 text-xs font-semibold transition-all border-b-2 ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-400 bg-blue-500/10'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Drawer Body */}
          <div className="p-6 space-y-6">
            {/* Risk Gauge Bar */}
            <div className="glass-panel p-5 space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">DistilBERT & Heuristic Threat Score</span>
                <span className={`text-2xl font-extrabold font-mono ${riskPercent >= 80 ? 'text-rose-400' : riskPercent >= 50 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {riskPercent}%
                </span>
              </div>
              <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-500 ${
                    riskPercent >= 80
                      ? 'bg-gradient-to-r from-amber-500 to-rose-500'
                      : 'bg-gradient-to-r from-emerald-500 to-amber-500'
                  }`}
                  style={{ width: `${riskPercent}%` }}
                />
              </div>
            </div>

            {/* TAB 1: Email Viewer */}
            {activeTab === 'email' && (
              <div className="space-y-4">
                <div className="glass-panel p-5 space-y-3 text-xs">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <span className="font-bold text-slate-200 text-sm">Email Metadata</span>
                    <button
                      onClick={() => handleCopy(alert.email?.sender || 'partner@suspicious-domain.net')}
                      className="text-[11px] font-mono text-cyan-400 hover:underline"
                    >
                      {copiedText === (alert.email?.sender || 'partner@suspicious-domain.net') ? 'Copied!' : 'Copy Sender'}
                    </button>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Sender:</span>
                      <button
                        onClick={() => onPivotIOC && onPivotIOC(alert.email?.sender || 'partner@suspicious-domain.net')}
                        className="text-cyan-400 font-bold hover:underline break-all text-left"
                      >
                        {alert.email?.sender || 'partner@suspicious-domain.net'}
                      </button>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Recipient:</span>
                      <span className="text-slate-200 break-all">{alert.email?.recipient || 'analyst@cybershield.io'}</span>
                    </div>
                  </div>
                </div>

                {/* Email Body Outlook Style Box */}
                <div className="glass-panel p-5 space-y-3">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Decoded Email Payload Body</span>
                  <div className="p-4 bg-slate-950/90 rounded-xl border border-slate-800 text-xs text-slate-200 font-sans whitespace-pre-wrap leading-relaxed">
                    {sampleEmailBody}
                  </div>
                </div>

                {/* Extracted Indicators Bar */}
                <div className="glass-panel p-5 space-y-3">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Extracted Threat Indicators (Click to Pivot)</span>
                  <div className="flex flex-wrap gap-2">
                    {['http://account-verify-sec.com/login', '185.220.101.5', 'remittance_report.exe'].map((ioc) => (
                      <button
                        key={ioc}
                        onClick={() => onPivotIOC && onPivotIOC(ioc)}
                        className="px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/30 font-mono text-xs hover:bg-rose-500/20 transition flex items-center space-x-1.5"
                      >
                        <span>🔍</span>
                        <span>{ioc}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: Explainable AI Tokens */}
            {activeTab === 'xai' && (
              <div className="glass-panel p-5 space-y-4 border-blue-500/30">
                <div className="flex items-center space-x-2 text-blue-400 font-bold text-sm">
                  <span>🧠</span>
                  <span>DistilBERT Explainable AI (XAI) Token Attention Rationale</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  The deep learning transformer model evaluated token weights across the email body and subject line.
                </p>
                <div className="space-y-2">
                  <span className="text-xs text-slate-300 font-semibold">Flagged High-Risk Tokens:</span>
                  <div className="flex flex-wrap gap-2">
                    {['unauthorized_login', 'verify_credentials', 'permanent_suspension', 'account-verify-sec.com', 'urgent_action'].map((tok, i) => (
                      <span key={i} className="px-3 py-1 text-xs font-mono rounded-lg bg-rose-500/15 text-rose-300 border border-rose-500/35">
                        {tok} (Weight: {(0.92 - i * 0.08).toFixed(2)})
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 3: ClamAV & YARA */}
            {activeTab === 'yara' && (
              <div className="glass-panel p-5 space-y-4">
                <h4 className="font-bold text-slate-200 text-sm flex items-center space-x-2">
                  <span>🛡️</span>
                  <span>Static Scanning Engine Verdicts</span>
                </h4>
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-300 font-bold">
                      <span>ClamAV Antivirus Scanner:</span>
                      <span className="text-rose-400">FOUND (Win32.Trojan.Agent.X2)</span>
                    </div>
                    <div className="text-[11px] text-slate-500">Scan engine signature version: 26842</div>
                  </div>

                  <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-300 font-bold">
                      <span>YARA Rule Engine Matches:</span>
                      <span className="text-amber-400">MATCHED (rule_phish_o365_credential_stealer)</span>
                    </div>
                    <div className="text-[11px] text-slate-500">Matched strings: $s1="verify your credentials", $s2="suspended"</div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: Raw MIME Headers */}
            {activeTab === 'headers' && (
              <div className="glass-panel p-5 space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-slate-300">Raw RFC822 Header Dump</span>
                  <button
                    onClick={() => handleCopy(sampleHeaders)}
                    className="text-[11px] text-cyan-400 hover:underline"
                  >
                    {copiedText === sampleHeaders ? 'Copied!' : 'Copy Headers'}
                  </button>
                </div>
                <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-slate-300 overflow-x-auto text-[11px] leading-relaxed">
                  {sampleHeaders}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* Drawer Footer Actions */}
        <div className="p-6 border-t border-slate-800 bg-slate-900/95 backdrop-blur space-y-3 sticky bottom-0 z-20">
          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider">Analyst Triage Decision Notes</label>
          <input
            type="text"
            placeholder="Add investigation comments before taking action..."
            value={triageComment}
            onChange={(e) => setTriageComment(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <div className="flex space-x-3 pt-1">
            <button
              onClick={() => onTriage('RESOLVED_QUARANTINED')}
              className="flex-1 py-3 bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white text-xs font-bold rounded-xl shadow-lg shadow-rose-500/20 transition"
            >
              Quarantine & Contain Email
            </button>
            <button
              onClick={() => onTriage('RESOLVED_FALSE_POSITIVE')}
              className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-semibold rounded-xl border border-slate-700 transition"
            >
              Mark False Positive
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

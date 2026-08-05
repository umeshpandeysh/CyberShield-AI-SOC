import React, { useState } from 'react';

interface ReportExporterProps {
  onExport: (format: 'pdf' | 'txt' | 'json') => void;
}

export const ReportExporter: React.FC<ReportExporterProps> = ({ onExport }) => {
  const [selectedFormat, setSelectedFormat] = useState<'pdf' | 'txt' | 'json'>('pdf');

  return (
    <div className="glass-panel p-6 space-y-4">
      <div>
        <h3 className="font-bold text-white text-base flex items-center space-x-2">
          <span>📄</span>
          <span>Executive & Compliance Report Generator</span>
        </h3>
        <p className="text-xs text-slate-400 mt-1">
          Export formal SOC incident investigation reports, ISO 27001 audit summaries, and threat intelligence metrics.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {[
          { id: 'pdf', title: 'Executive Summary (.pdf)', desc: 'Formal CISO summary report format' },
          { id: 'txt', title: 'SOC Investigation (.txt)', desc: 'Raw analyst investigation notes & timeline' },
          { id: 'json', title: 'Machine STIX/TAXII (.json)', desc: 'Structured threat indicator JSON payload' },
        ].map((fmt) => (
          <button
            key={fmt.id}
            onClick={() => setSelectedFormat(fmt.id as any)}
            className={`p-4 rounded-xl border text-left transition-all ${
              selectedFormat === fmt.id
                ? 'bg-blue-600/20 border-blue-500/50 ring-1 ring-blue-500'
                : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
            }`}
          >
            <div className="font-bold text-xs text-white">{fmt.title}</div>
            <div className="text-[11px] text-slate-400 mt-1">{fmt.desc}</div>
          </button>
        ))}
      </div>

      <div className="flex justify-end pt-2">
        <button
          onClick={() => onExport(selectedFormat)}
          className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-blue-500/20 transition flex items-center space-x-2"
        >
          <span>📥</span>
          <span>Generate & Download Report</span>
        </button>
      </div>
    </div>
  );
};

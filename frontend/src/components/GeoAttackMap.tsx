import React from 'react';

export const GeoAttackMap: React.FC = () => {
  const regions = [
    { region: 'Eastern Europe', threats: 142, riskLevel: 'Critical', color: 'bg-rose-500', barWidth: '85%' },
    { region: 'Asia Pacific', threats: 98, riskLevel: 'High', color: 'bg-amber-500', barWidth: '65%' },
    { region: 'North America', threats: 45, riskLevel: 'Medium', color: 'bg-blue-500', barWidth: '35%' },
    { region: 'Western Europe', threats: 32, riskLevel: 'Low', color: 'bg-emerald-500', barWidth: '25%' },
    { region: 'Latin America', threats: 19, riskLevel: 'Low', color: 'bg-emerald-500', barWidth: '15%' },
  ];

  return (
    <div className="glass-panel p-6 space-y-4">
      <div className="flex justify-between items-center border-b border-slate-800 pb-3">
        <div>
          <h3 className="font-bold text-white text-base flex items-center space-x-2">
            <span>🌍</span>
            <span>Geographic Threat Origin & Vector Map</span>
          </h3>
          <p className="text-xs text-slate-400">Global attack origin distribution and target region breakdown</p>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 text-cyan-400 border border-slate-800 font-bold">
          24h Global Feed
        </span>
      </div>

      <div className="space-y-3 pt-1">
        {regions.map((r) => (
          <div key={r.region} className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between items-center">
              <span className="font-semibold text-slate-200">{r.region}</span>
              <div className="flex items-center space-x-3">
                <span className="text-slate-400">{r.threats} incident attempts</span>
                <span className={`px-2 py-0.2 rounded text-[10px] uppercase font-bold ${
                  r.riskLevel === 'Critical' ? 'bg-rose-500/20 text-rose-300' : r.riskLevel === 'High' ? 'bg-amber-500/20 text-amber-300' : 'bg-blue-500/20 text-blue-300'
                }`}>
                  {r.riskLevel}
                </span>
              </div>
            </div>
            <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
              <div className={`h-full ${r.color} transition-all duration-500`} style={{ width: r.barWidth }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

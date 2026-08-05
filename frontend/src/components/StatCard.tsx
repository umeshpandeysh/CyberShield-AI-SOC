import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  accentColor: 'emerald' | 'amber' | 'rose' | 'blue' | 'purple';
  subtitle?: string;
  badgeText?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon,
  accentColor,
  subtitle,
  badgeText,
}) => {
  const colorMap = {
    emerald: {
      border: 'border-l-emerald-500',
      text: 'text-emerald-400',
      bgIcon: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      glow: 'hover:border-emerald-500/40',
    },
    amber: {
      border: 'border-l-amber-500',
      text: 'text-amber-400',
      bgIcon: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      glow: 'hover:border-amber-500/40',
    },
    rose: {
      border: 'border-l-rose-500',
      text: 'text-rose-400',
      bgIcon: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      glow: 'hover:border-rose-500/40',
    },
    blue: {
      border: 'border-l-blue-500',
      text: 'text-blue-400',
      bgIcon: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      glow: 'hover:border-blue-500/40',
    },
    purple: {
      border: 'border-l-purple-500',
      text: 'text-purple-400',
      bgIcon: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      glow: 'hover:border-purple-500/40',
    },
  };

  const style = colorMap[accentColor];

  return (
    <div className={`glass-panel p-5 border-l-4 ${style.border} ${style.glow} transition-all duration-200 group`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
        <div className={`p-2.5 rounded-xl border ${style.bgIcon} transition-transform group-hover:scale-110`}>
          {icon}
        </div>
      </div>
      <div className="mt-3 flex items-baseline justify-between">
        <span className={`text-3xl font-extrabold font-mono tracking-tight ${style.text}`}>{value}</span>
        {badgeText && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
            {badgeText}
          </span>
        )}
      </div>
      {subtitle && <p className="mt-2 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
};

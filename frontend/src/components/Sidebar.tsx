import React from 'react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: any) => void;
  alertsCount: number;
  casesCount: number;
  userRole?: string;
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  alertsCount,
  casesCount,
  userRole,
  collapsed,
  setCollapsed,
}) => {
  const mainNavItems = [
    {
      id: 'dashboard',
      label: 'SOC Workspace',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
        </svg>
      ),
    },
    {
      id: 'alerts',
      label: 'Threat Queue',
      badge: alertsCount > 0 ? alertsCount : undefined,
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
    },
    {
      id: 'cases',
      label: 'Incident Cases',
      badge: casesCount > 0 ? casesCount : undefined,
      badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
      ),
    },
    {
      id: 'threat_intel',
      label: 'IOC Intelligence',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
    },
  ];

  const secondaryNavItems = [
    {
      id: 'tasks',
      label: 'Async Engine',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
    },
    {
      id: 'analytics',
      label: 'Executive Reports',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
    },
    {
      id: 'admin',
      label: 'Admin & Settings',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      ),
    },
  ];

  return (
    <aside
      aria-label="Main Navigation"
      className={`fixed top-0 left-0 bottom-0 z-40 bg-[#0b1120]/95 backdrop-blur-2xl border-r border-slate-800/80 transition-all duration-300 flex flex-col justify-between ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      <div>
        {/* Header Branding */}
        <div className="h-16 px-4 flex items-center justify-between border-b border-slate-800/80">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="h-10 w-10 min-w-[2.5rem] rounded-xl bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-lg shadow-blue-500/20 border border-blue-400/30">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            {!collapsed && (
              <div className="transition-opacity duration-200">
                <span className="font-bold text-base tracking-tight text-white block leading-none">CyberShield</span>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest block mt-1">Autonomous XDR</span>
              </div>
            )}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition focus-visible:ring-2 focus-visible:ring-blue-500"
            aria-label={collapsed ? 'Expand Navigation Sidebar' : 'Collapse Navigation Sidebar'}
          >
            <svg className={`w-5 h-5 transition-transform ${collapsed ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
            </svg>
          </button>
        </div>

        {/* Primary Navigation */}
        <div className="p-3 space-y-6">
          <div className="space-y-1">
            {!collapsed && (
              <span className="px-3 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500 block mb-2">
                Operations
              </span>
            )}
            {mainNavItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-semibold transition-all focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    isActive
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40 shadow-lg shadow-blue-500/10'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                  }`}
                  title={collapsed ? item.label : undefined}
                >
                  <div className="flex items-center space-x-3">
                    <span className={isActive ? 'text-blue-400' : 'text-slate-400'}>{item.icon}</span>
                    {!collapsed && <span>{item.label}</span>}
                  </div>
                  {!collapsed && item.badge !== undefined && (
                    <span className={`px-2 py-0.5 text-[11px] font-mono font-bold rounded-full border ${item.badgeColor}`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="space-y-1 pt-2 border-t border-slate-800/60">
            {!collapsed && (
              <span className="px-3 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500 block mb-2">
                Management
              </span>
            )}
            {secondaryNavItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-semibold transition-all focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    isActive
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40 shadow-lg shadow-blue-500/10'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                  }`}
                  title={collapsed ? item.label : undefined}
                >
                  <div className="flex items-center space-x-3">
                    <span className={isActive ? 'text-blue-400' : 'text-slate-400'}>{item.icon}</span>
                    {!collapsed && <span>{item.label}</span>}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Footer System Status */}
      {!collapsed && (
        <div className="p-4 border-t border-slate-800/80 bg-slate-900/40">
          <div className="glass-card p-3 flex items-center justify-between text-xs">
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
              <span className="text-slate-300 font-medium">SOC Engine Online</span>
            </div>
            <span className="font-mono text-[10px] text-slate-500">v1.0.0</span>
          </div>
        </div>
      )}
    </aside>
  );
};

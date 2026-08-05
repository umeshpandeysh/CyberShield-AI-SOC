import React from 'react';
import { User } from '../types';

interface NavbarProps {
  user: User;
  onLogout: () => void;
  wsStatus: 'connected' | 'disconnected';
  onSearchSubmit?: (query: string) => void;
  sidebarCollapsed: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  user,
  onLogout,
  wsStatus,
  sidebarCollapsed,
}) => {
  return (
    <header
      className={`h-16 fixed top-0 right-0 z-30 bg-[#0d1527]/85 backdrop-blur-xl border-b border-slate-800/80 px-6 flex items-center justify-between transition-all duration-300 ${
        sidebarCollapsed ? 'left-20' : 'left-64'
      }`}
    >
      {/* Search Input Bar */}
      <div className="flex items-center space-x-4 flex-1 max-w-md">
        <div className="relative w-full">
          <svg className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search alerts, cases, IOCs, IP addresses..."
            className="w-full bg-slate-900/90 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/40 transition"
          />
        </div>
      </div>

      {/* Right Navbar Controls */}
      <div className="flex items-center space-x-5">
        {/* Live Telemetry WebSocket Pill */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900/80 border border-slate-800 text-xs">
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${wsStatus === 'connected' ? 'bg-emerald-400' : 'bg-rose-400'}`} />
            <span className={`relative inline-flex rounded-full h-2 w-2 ${wsStatus === 'connected' ? 'bg-emerald-500' : 'bg-rose-500'}`} />
          </span>
          <span className="font-mono font-medium text-slate-300 text-[11px]">
            {wsStatus === 'connected' ? 'LIVE TELEMETRY' : 'OFFLINE'}
          </span>
        </div>

        {/* User Card & Logout */}
        <div className="flex items-center space-x-3 border-l border-slate-800/80 pl-5">
          <div className="h-8 w-8 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center font-bold text-xs text-white shadow-md shadow-blue-500/20 border border-blue-400/30">
            {user.email.charAt(0).toUpperCase()}
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-xs font-semibold text-slate-200 leading-none">{user.email}</div>
            <div className="mt-1 flex items-center space-x-1.5">
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                {user.role}
              </span>
            </div>
          </div>
          <button
            onClick={onLogout}
            className="p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition border border-transparent hover:border-rose-500/20"
            title="Sign Out"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
          </button>
        </div>
      </div>
    </header>
  );
};

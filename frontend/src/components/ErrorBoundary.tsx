import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('CyberShield UI ErrorBoundary caught an exception:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#070c18] text-slate-100 flex items-center justify-center p-6 soc-grid-bg">
          <div className="glass-panel w-full max-w-lg p-8 shadow-2xl space-y-4 border-rose-500/40 text-center">
            <div className="inline-flex h-14 w-14 rounded-2xl bg-rose-500/20 text-rose-400 items-center justify-center text-2xl font-bold border border-rose-500/40 mb-2">
              ⚠️
            </div>
            <h2 className="text-xl font-bold text-white">SOC Telemetry Rendering Exception</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              An unexpected component rendering error occurred. The application state has been preserved.
            </p>
            {this.state.error && (
              <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono text-rose-300 text-left overflow-x-auto">
                {this.state.error.toString()}
              </pre>
            )}
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-blue-500/20 transition"
            >
              Reload SOC Command Center
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

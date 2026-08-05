import React, { useState, useEffect } from 'react';
import { api, getAuthToken, removeAuthToken, setAuthToken } from './api';
import { User, AlertSummary, AlertDetail, CaseSummary, CaseDetail, TaskRecord, ProviderHealth, MetricsSummary } from './types';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { StatCard } from './components/StatCard';
import { AlertTriageDrawer } from './components/AlertTriageDrawer';
import { CaseWorkspaceDrawer } from './components/CaseWorkspaceDrawer';
import { MitreMatrix } from './components/MitreMatrix';
import { IocGraphView } from './components/IocGraphView';
import { GeoAttackMap } from './components/GeoAttackMap';
import { ReportExporter } from './components/ReportExporter';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'cases' | 'threat_intel' | 'tasks' | 'analytics' | 'admin'>('dashboard');

  // Auth form state
  const [email, setEmail] = useState('analyst@cybershield.io');
  const [password, setPassword] = useState('Password123!');
  const [loginError, setLoginError] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);

  // Dashboard Data State
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [providers, setProviders] = useState<ProviderHealth[]>([]);
  const [wsStatus, setWsStatus] = useState<'connected' | 'disconnected'>('disconnected');

  // Selected Detail Drawers State
  const [selectedAlert, setSelectedAlert] = useState<AlertDetail | null>(null);
  const [selectedCase, setSelectedCase] = useState<CaseDetail | null>(null);
  const [iocSearch, setIocSearch] = useState('');
  const [iocResult, setIocResult] = useState<any>(null);
  const [triageComment, setTriageComment] = useState('');

  // Ingestion State
  const [ingestFile, setIngestFile] = useState<File | null>(null);
  const [ingestStatus, setIngestStatus] = useState<string>('');

  // Admin / User Creation State
  const [usersList, setUsersList] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('Analyst_L1');

  // Case creation state
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseSeverity, setNewCaseSeverity] = useState('High');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [newNoteContent, setNewNoteContent] = useState('');

  // Settings state
  const [settingsData, setSettingsData] = useState<any>(null);
  const [confidenceThreshold, setConfidenceThreshold] = useState<number>(0.82);

  // Filters state
  const [alertFilterStatus, setAlertFilterStatus] = useState<string>('ALL');

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    if (user) {
      loadAllData();
      connectWebSocket();
    }
  }, [user]);

  const checkAuth = async () => {
    if (getAuthToken()) {
      try {
        const u = await api.getMe();
        setUser(u);
      } catch {
        removeAuthToken();
      }
    }
    setLoading(false);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setAuthSubmitting(true);
    try {
      const res = await api.login(email, password);
      setAuthToken(res.access_token);
      const u = await api.getMe();
      setUser(u);
    } catch (err: any) {
      setLoginError(err.message || 'Login failed');
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleLogout = () => {
    removeAuthToken();
    setUser(null);
  };

  const loadAllData = async () => {
    try {
      const m = await api.getMetricsSummary();
      setMetrics(m);

      const al = await api.listAlerts();
      setAlerts(al.data || []);

      const cs = await api.listCases();
      setCases(cs.data || []);

      const ts = await api.listTasks();
      setTasks(ts.data || []);

      const pr = await api.getProviderHealth();
      setProviders(pr || []);

      const st = await api.getSettings();
      setSettingsData(st);
      if (st && st.confidence_threshold) setConfidenceThreshold(st.confidence_threshold);

      if (user?.role === 'Admin') {
        const usrs = await api.listUsers();
        setUsersList(usrs || []);
        const logs = await api.getAuditLogs();
        setAuditLogs(logs || []);
      }
    } catch (e) {
      console.error('Error loading dashboard data', e);
    }
  };

  const connectWebSocket = () => {
    const rawBase = ((import.meta as any).env?.VITE_API_BASE_URL as string) || '';
    const wsHost = rawBase ? rawBase.replace(/^https?:\/\//, '').replace(/\/$/, '') : window.location.host;
    const protocol = (rawBase ? rawBase.startsWith('https') : window.location.protocol === 'https:') ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${wsHost}/ws/notifications`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => setWsStatus('connected');
    socket.onclose = () => setWsStatus('disconnected');
    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        console.log('Live WS Event:', msg);
        if (msg.event_type === 'ALERT_CREATED' || msg.event_type === 'TASK_UPDATED') {
          loadAllData();
        }
      } catch {
        // pass
      }
    };
  };

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ingestFile) return;
    setIngestStatus('Queuing EML file...');
    try {
      const res = await api.ingestEmailAsync(ingestFile);
      setIngestStatus(`File queued successfully! Task ID: ${res.task_id.slice(0, 8)}...`);
      setIngestFile(null);
      loadAllData();
    } catch (err: any) {
      setIngestStatus(`Error: ${err.message}`);
    }
  };

  const handleInspectAlert = async (id: string) => {
    try {
      const detail = await api.getAlertDetail(id);
      setSelectedAlert(detail);
    } catch (e: any) {
      alert(`Could not load alert: ${e.message}`);
    }
  };

  const handleTriageAlert = async (status: string) => {
    if (!selectedAlert) return;
    try {
      await api.triageAlert(selectedAlert.id, status, triageComment);
      alert(`Alert triage status updated to ${status}`);
      setSelectedAlert(null);
      setTriageComment('');
      loadAllData();
    } catch (e: any) {
      alert(`Triage failed: ${e.message}`);
    }
  };

  const handleInspectCase = async (id: string) => {
    try {
      const detail = await api.getCaseDetail(id);
      setSelectedCase(detail);
    } catch (e: any) {
      alert(`Could not load case: ${e.message}`);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createCase({
        title: newCaseTitle,
        description: newCaseDesc,
        severity: newCaseSeverity,
        tags: 'soc,investigation',
      });
      alert('Case created successfully');
      setNewCaseTitle('');
      setNewCaseDesc('');
      loadAllData();
    } catch (e: any) {
      alert(`Error creating case: ${e.message}`);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNoteContent) return;
    try {
      await api.addCaseNote(selectedCase.id, newNoteContent);
      setNewNoteContent('');
      handleInspectCase(selectedCase.id);
    } catch (e: any) {
      alert(`Error adding note: ${e.message}`);
    }
  };

  const handleSearchIOC = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!iocSearch) return;
    try {
      const res = await api.enrichSingleIOC(iocSearch);
      setIocResult(res);
    } catch (e: any) {
      alert(`IOC Search failed: ${e.message}`);
    }
  };

  const handlePivotIOC = async (ioc: string) => {
    setSelectedAlert(null);
    setSelectedCase(null);
    setIocSearch(ioc);
    setActiveTab('threat_intel');
    try {
      const res = await api.enrichSingleIOC(ioc);
      setIocResult(res);
    } catch (e: any) {
      console.warn(`IOC Pivot notice: ${e.message}`);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createUser({ email: newEmail, password: newPassword, role: newRole });
      alert(`User ${newEmail} created successfully`);
      setNewEmail('');
      setNewPassword('');
      loadAllData();
    } catch (e: any) {
      alert(`Create user failed: ${e.message}`);
    }
  };

  const handleUpdateSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.updateSettings({ confidence_threshold: confidenceThreshold });
      alert('Settings updated successfully');
      loadAllData();
    } catch (e: any) {
      alert(`Update settings failed: ${e.message}`);
    }
  };

  const handleExportReport = async (format: 'pdf' | 'txt' | 'json') => {
    try {
      const summaryText = await api.getCaseReportText(cases[0]?.id || '');
      let blob: Blob;
      let filename: string;

      if (format === 'json') {
        const payload = {
          report_title: 'CyberShield-AI-SOC Threat Audit',
          timestamp: new Date().toISOString(),
          statistics: metrics?.statistics,
          open_cases_count: cases.length,
          alerts_count: alerts.length,
          report_body: summaryText,
        };
        blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        filename = 'executive_soc_threat_report.json';
      } else {
        blob = new Blob([summaryText], { type: 'text/plain' });
        filename = `executive_soc_threat_report.${format}`;
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
    } catch (e: any) {
      alert(`Failed to export report: ${e.message}`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#070c18] text-slate-300 soc-grid-bg">
        <div className="flex flex-col items-center space-y-4">
          <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-xl shadow-blue-500/20 border border-blue-400/30 animate-bounce">
            🛡️
          </div>
          <div className="text-sm font-mono text-cyan-400 tracking-wider animate-pulse">
            INITIALIZING CYBERSHIELD-AI-SOC ENGINE...
          </div>
        </div>
      </div>
    );
  }

  // --- Login Screen ---
  if (!user) {
    return (
      <div className="min-h-screen bg-[#070c18] text-slate-100 flex items-center justify-center p-4 soc-grid-bg">
        <div className="glass-panel w-full max-w-md p-8 shadow-2xl space-y-6 border-slate-800">
          <div className="text-center space-y-2">
            <div className="inline-flex h-14 w-14 rounded-2xl bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-500 items-center justify-center text-white shadow-lg shadow-blue-500/25 border border-blue-400/30 mb-2">
              🛡️
            </div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">CyberShield-AI-SOC</h1>
            <p className="text-xs text-slate-400">Enterprise Autonomous Threat Detection & SOC Operations</p>
          </div>

          {loginError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/40 rounded-xl text-rose-300 text-xs flex items-center space-x-2">
              <span>⚠️</span>
              <span>{loginError}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Analyst Account Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/80 transition"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/80 transition"
              />
            </div>

            <button
              type="submit"
              disabled={authSubmitting}
              className="w-full py-3 bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white font-bold text-xs rounded-xl shadow-lg shadow-blue-500/25 transition disabled:opacity-50"
            >
              {authSubmitting ? 'Authenticating Session...' : 'Sign In to SOC Center'}
            </button>
          </form>

          {/* Quick Preset Credentials */}
          <div className="pt-4 border-t border-slate-800/80 space-y-2">
            <span className="text-[10px] font-mono text-slate-500 block text-center uppercase tracking-wider">Demo Credentials</span>
            <div className="flex space-x-2">
              <button
                type="button"
                onClick={() => {
                  setEmail('analyst@cybershield.io');
                  setPassword('Password123!');
                }}
                className="flex-1 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 text-[11px] font-mono rounded-lg border border-slate-800 transition"
              >
                Analyst L2
              </button>
              <button
                type="button"
                onClick={() => {
                  setEmail('admin@cybershield.io');
                  setPassword('Password123!');
                }}
                className="flex-1 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 text-[11px] font-mono rounded-lg border border-slate-800 transition"
              >
                Admin User
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const filteredAlerts = alertFilterStatus === 'ALL'
    ? alerts
    : alerts.filter((a) => a.status === alertFilterStatus);

  return (
    <div className="min-h-screen bg-[#070c18] text-slate-100 soc-grid-bg flex">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertsCount={alerts.length}
        casesCount={cases.length}
        userRole={user.role}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
      />

      {/* Main Content Area */}
      <div className={`flex-1 transition-all duration-300 flex flex-col ${sidebarCollapsed ? 'ml-20' : 'ml-64'}`}>
        <Navbar
          user={user}
          onLogout={handleLogout}
          wsStatus={wsStatus}
          sidebarCollapsed={sidebarCollapsed}
        />

        <main className="mt-16 p-6 flex-1 space-y-6 max-w-7xl mx-auto w-full">
          {/* Quick RFC822 EML Ingestion Banner */}
          <section className="glass-panel p-5 flex flex-col sm:flex-row items-center justify-between gap-4 border-blue-500/20">
            <div>
              <h3 className="font-bold text-white text-sm flex items-center space-x-2">
                <span>⚡</span>
                <span>Async RFC822 Email Suspicion Ingestion</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Upload suspicious `.eml` files to trigger Celery background parsing, ClamAV/YARA scanning, and DistilBERT AI inference.
              </p>
            </div>
            <form onSubmit={handleIngest} className="flex items-center space-x-3 w-full sm:w-auto">
              <input
                type="file"
                accept=".eml"
                onChange={(e) => setIngestFile(e.target.files?.[0] || null)}
                className="text-xs text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700 cursor-pointer"
              />
              <button
                type="submit"
                disabled={!ingestFile}
                className="px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 text-white text-xs font-bold rounded-xl shadow-md shadow-blue-500/20 transition whitespace-nowrap"
              >
                Upload & Inspect
              </button>
            </form>
            {ingestStatus && (
              <span className="text-xs font-mono px-3 py-1 rounded-full bg-blue-500/10 text-cyan-400 border border-blue-500/30">
                {ingestStatus}
              </span>
            )}
          </section>

          {/* TAB 1: Dashboard Overview */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              {/* KPI Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                  title="Processed Today"
                  value={metrics?.statistics?.total_processed_today || 0}
                  icon={
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  }
                  accentColor="emerald"
                  subtitle="Completed email inspection tasks"
                  badgeText="24h"
                  trendPercentage="+12.4%"
                />
                <StatCard
                  title="Unresolved Alerts"
                  value={metrics?.statistics?.unresolved_alerts_count || 0}
                  icon={
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  }
                  accentColor="amber"
                  subtitle="Pending analyst triage"
                  badgeText="Action Needed"
                  trendPercentage="-5.2%"
                />
                <StatCard
                  title="Quarantined Threats"
                  value={metrics?.statistics?.quarantined_today || 0}
                  icon={
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                    </svg>
                  }
                  accentColor="rose"
                  subtitle="Confirmed malicious emails"
                  badgeText="High Risk"
                  trendPercentage="+8.1%"
                />
                <StatCard
                  title="Active SOC Cases"
                  value={cases.length}
                  icon={
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                    </svg>
                  }
                  accentColor="blue"
                  subtitle="Open incident investigations"
                  badgeText="Active"
                  trendPercentage="+2"
                />
              </div>

              {/* Geographic Threat Origin Map */}
              <GeoAttackMap />

              {/* Recent High-Risk Alerts Table */}
              <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="font-bold text-lg text-white">Recent High-Risk Threat Alerts</h3>
                    <p className="text-xs text-slate-400">Latest threat triggers requiring analyst evaluation</p>
                  </div>
                  <button
                    onClick={() => setActiveTab('alerts')}
                    className="text-xs font-semibold text-blue-400 hover:text-blue-300 transition"
                  >
                    View All Queue →
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Sender</th>
                        <th>Subject</th>
                        <th>Risk Score</th>
                        <th>Status</th>
                        <th className="text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.length > 0 ? (
                        alerts.slice(0, 5).map((a) => (
                          <tr key={a.id}>
                            <td className="font-mono text-slate-300">{a.sender}</td>
                            <td className="text-slate-200">{a.subject || '(No Subject)'}</td>
                            <td>
                              <span
                                className={`px-2.5 py-0.5 rounded-full font-mono font-bold text-[11px] ${
                                  a.risk_score >= 0.8
                                    ? 'badge-critical'
                                    : a.risk_score >= 0.5
                                    ? 'badge-high'
                                    : 'badge-low'
                                }`}
                              >
                                {Math.round(a.risk_score * 100)}%
                              </span>
                            </td>
                            <td>
                              <span className="px-2.5 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700/80 font-mono text-[11px]">
                                {a.status}
                              </span>
                            </td>
                            <td className="text-right">
                              <button
                                onClick={() => handleInspectAlert(a.id)}
                                className="px-3 py-1 bg-blue-600/80 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition shadow"
                              >
                                Inspect Triage
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="text-center py-6 text-slate-500 text-xs">
                            No active threat alerts recorded yet.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Threat Alerts Queue */}
          {activeTab === 'alerts' && (
            <div className="glass-panel p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="font-bold text-lg text-white">Threat Alert Queue & Triage Desk</h3>
                  <p className="text-xs text-slate-400">Filter, inspect, and quarantine suspicious emails</p>
                </div>
                <div className="flex items-center space-x-2">
                  {['ALL', 'OPEN', 'RESOLVED_QUARANTINED', 'RESOLVED_FALSE_POSITIVE'].map((st) => (
                    <button
                      key={st}
                      onClick={() => setAlertFilterStatus(st)}
                      className={`px-3 py-1.5 text-xs font-mono rounded-lg transition ${
                        alertFilterStatus === st
                          ? 'bg-blue-600 text-white font-bold'
                          : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Alert ID</th>
                      <th>Sender</th>
                      <th>Subject</th>
                      <th>Risk Score</th>
                      <th>Status</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAlerts.length > 0 ? (
                      filteredAlerts.map((a) => (
                        <tr key={a.id}>
                          <td className="font-mono text-slate-400">{a.id.slice(0, 8)}...</td>
                          <td className="font-mono text-slate-300">{a.sender}</td>
                          <td className="text-slate-200">{a.subject || '(No Subject)'}</td>
                          <td>
                            <span className="font-bold text-rose-400 font-mono text-sm">
                              {Math.round(a.risk_score * 100)}%
                            </span>
                          </td>
                          <td>
                            <span className="px-2.5 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700/80 font-mono text-[11px]">
                              {a.status}
                            </span>
                          </td>
                          <td className="text-right">
                            <button
                              onClick={() => handleInspectAlert(a.id)}
                              className="px-3 py-1 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-lg text-xs font-semibold shadow transition"
                            >
                              Inspect & Triage
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} className="text-center py-8 text-slate-500 text-xs">
                          No alerts match the selected status filter.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: Incident Cases Workspace */}
          {activeTab === 'cases' && (
            <div className="space-y-6">
              {/* Create Case Form */}
              <div className="glass-panel p-6 space-y-4">
                <h3 className="font-bold text-lg text-white">Open New SOC Incident Case</h3>
                <form onSubmit={handleCreateCase} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <input
                    type="text"
                    placeholder="Case Title"
                    required
                    value={newCaseTitle}
                    onChange={(e) => setNewCaseTitle(e.target.value)}
                    className="bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                  <select
                    value={newCaseSeverity}
                    onChange={(e) => setNewCaseSeverity(e.target.value)}
                    className="bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="Critical">Critical Severity</option>
                    <option value="High">High Severity</option>
                    <option value="Medium">Medium Severity</option>
                    <option value="Low">Low Severity</option>
                  </select>
                  <button
                    type="submit"
                    className="py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-bold text-xs rounded-xl shadow transition"
                  >
                    Create Case
                  </button>
                </form>
              </div>

              {/* Cases Datatable */}
              <div className="glass-panel p-6">
                <h3 className="font-bold text-lg text-white mb-4">Active Incident Cases Workspace</h3>
                <div className="overflow-x-auto">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Case ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th className="text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cases.length > 0 ? (
                        cases.map((c) => (
                          <tr key={c.id}>
                            <td className="font-mono text-slate-400">{c.id.slice(0, 8)}...</td>
                            <td className="text-slate-200 font-medium">{c.title}</td>
                            <td>
                              <span
                                className={`px-2.5 py-0.5 rounded-full font-mono text-[11px] font-bold ${
                                  c.severity === 'Critical'
                                    ? 'badge-critical'
                                    : c.severity === 'High'
                                    ? 'badge-high'
                                    : 'badge-medium'
                                }`}
                              >
                                {c.severity}
                              </span>
                            </td>
                            <td>
                              <span className="px-2.5 py-0.5 rounded-md bg-slate-800 text-slate-300 font-mono text-[11px]">
                                {c.status}
                              </span>
                            </td>
                            <td className="text-right">
                              <button
                                onClick={() => handleInspectCase(c.id)}
                                className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition"
                              >
                                Investigate Workspace
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="text-center py-8 text-slate-500 text-xs">
                            No incident cases opened yet.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: Threat Intelligence Explorer & MITRE Matrix */}
          {activeTab === 'threat_intel' && (
            <div className="space-y-6">
              {/* MITRE ATT&CK Framework Navigator */}
              <MitreMatrix />

              {/* IOC Relationship Graph View */}
              <IocGraphView />

              <div className="glass-panel p-6 space-y-4">
                <div>
                  <h3 className="font-bold text-lg text-white">IOC Threat Intelligence Explorer</h3>
                  <p className="text-xs text-slate-400">Search URLs, domains, IP addresses, MD5/SHA256 hashes across VirusTotal, AbuseIPDB, URLHaus, OTX, OpenPhish.</p>
                </div>
                <form onSubmit={handleSearchIOC} className="flex space-x-3">
                  <input
                    type="text"
                    placeholder="Enter IOC indicator (e.g. http://phish-site.com/login or 192.168.1.1)"
                    required
                    value={iocSearch}
                    onChange={(e) => setIocSearch(e.target.value)}
                    className="flex-1 bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                  />
                  <button
                    type="submit"
                    className="px-6 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold rounded-xl shadow transition"
                  >
                    Enrich Indicator
                  </button>
                </form>

                {iocResult && (
                  <div className="p-5 bg-slate-900/90 rounded-xl border border-slate-800 space-y-3 font-mono text-xs animate-fade-in">
                    <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                      <span className="font-bold text-slate-200 text-sm">Indicator: {iocResult.ioc}</span>
                      <span
                        className={`px-3 py-1 rounded-full uppercase font-bold text-xs ${
                          iocResult.overall_verdict === 'malicious'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}
                      >
                        Verdict: {iocResult.overall_verdict}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-slate-400">
                      <div>Confidence: <strong className="text-white">{(iocResult.overall_confidence * 100).toFixed(0)}%</strong></div>
                      <div>Confirming Feeds: <strong className="text-white">{iocResult.confirming_malicious_providers}</strong></div>
                      <div className="col-span-2">Tags: <span className="text-cyan-400">{iocResult.tags?.join(', ') || 'None'}</span></div>
                    </div>
                  </div>
                )}
              </div>

              {/* Provider Circuit Breaker Monitor */}
              <div className="glass-panel p-6 space-y-4">
                <h3 className="font-bold text-lg text-white">Threat Feed Provider Circuit Breaker Health</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {providers.map((p) => (
                    <div key={p.provider} className="glass-card p-4 space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="font-bold text-white uppercase text-xs">{p.provider}</span>
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-xs font-mono ${
                            p.health === 'HEALTHY' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {p.health}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 font-mono">Circuit State: {p.circuit_state}</div>
                      <div className="text-xs text-slate-400 font-mono">Requests Processed: {p.total_requests}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: Async Pipeline Tasks */}
          {activeTab === 'tasks' && (
            <div className="glass-panel p-6 space-y-4">
              <h3 className="font-bold text-lg text-white">Live Celery Task Execution Monitor</h3>
              <div className="overflow-x-auto">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Task ID</th>
                      <th>Task Type</th>
                      <th>Status</th>
                      <th>Retries</th>
                      <th>Created At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((t) => (
                      <tr key={t.id}>
                        <td className="text-slate-300 font-mono">{t.id.slice(0, 12)}...</td>
                        <td className="text-slate-400 font-mono">{t.task_type}</td>
                        <td>
                          <span
                            className={`px-2.5 py-0.5 rounded-full font-bold text-[11px] font-mono ${
                              t.status === 'Completed'
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            }`}
                          >
                            {t.status}
                          </span>
                        </td>
                        <td className="text-slate-400 font-mono">{t.retry_count}</td>
                        <td className="text-slate-500 font-mono">{t.created_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: Analytics & Executive Reports */}
          {activeTab === 'analytics' && (
            <div className="space-y-6">
              {/* Executive & Audit Report Generator */}
              <ReportExporter onExport={handleExportReport} />

              <GeoAttackMap />
            </div>
          )}

          {/* TAB 7: Admin & Settings */}
          {activeTab === 'admin' && (
            <div className="space-y-6">
              {/* Settings Form */}
              <div className="glass-panel p-6 space-y-4">
                <h3 className="font-bold text-lg text-white">Detection Threshold Settings</h3>
                <form onSubmit={handleUpdateSettings} className="space-y-3 max-w-md">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                      AI Phishing Confidence Threshold
                    </label>
                    <input
                      type="number"
                      step="0.01"
                      min="0"
                      max="1"
                      value={confidenceThreshold}
                      onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
                      className="w-full bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                    />
                  </div>
                  <button type="submit" className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-xl shadow transition">
                    Save Detection Settings
                  </button>
                </form>
              </div>

              {/* User Administration */}
              {user.role === 'Admin' && (
                <div className="glass-panel p-6 space-y-4">
                  <h3 className="font-bold text-lg text-white">Analyst Account Management</h3>
                  <form onSubmit={handleCreateUser} className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                    <input
                      type="email"
                      placeholder="Analyst Email"
                      required
                      value={newEmail}
                      onChange={(e) => setNewEmail(e.target.value)}
                      className="bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white"
                    />
                    <input
                      type="password"
                      placeholder="Password"
                      required
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white"
                    />
                    <select
                      value={newRole}
                      onChange={(e) => setNewRole(e.target.value)}
                      className="bg-slate-900/90 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white"
                    >
                      <option value="Analyst_L1">Analyst_L1</option>
                      <option value="Analyst_L2">Analyst_L2</option>
                      <option value="Admin">Admin</option>
                    </select>
                    <button type="submit" className="py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 text-white text-xs font-bold rounded-xl shadow">
                      Create Account
                    </button>
                  </form>

                  <div className="overflow-x-auto pt-2">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>User Email</th>
                          <th>Role</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {usersList.map((u) => (
                          <tr key={u.id}>
                            <td className="text-slate-300 font-mono">{u.email}</td>
                            <td className="text-slate-400 font-mono">{u.role}</td>
                            <td className="text-emerald-400 font-mono">{u.is_active ? 'Active' : 'Inactive'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      {/* Slide-over Alert Triage Drawer */}
      <AlertTriageDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        triageComment={triageComment}
        setTriageComment={setTriageComment}
        onTriage={handleTriageAlert}
        onPivotIOC={handlePivotIOC}
      />

      {/* Master-detail Case Workspace Drawer */}
      <CaseWorkspaceDrawer
        caseDetail={selectedCase}
        onClose={() => setSelectedCase(null)}
        newNoteContent={newNoteContent}
        setNewNoteContent={setNewNoteContent}
        onAddNote={handleAddNote}
        onPivotIOC={handlePivotIOC}
      />
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import { api, getAuthToken, removeAuthToken, setAuthToken } from './api';
import { User, AlertSummary, CaseSummary, TaskRecord, ProviderHealth } from './types';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'cases' | 'threat_intel' | 'tasks' | 'analytics' | 'admin'>('dashboard');

  // Auth form state
  const [email, setEmail] = useState('analyst@cybershield.io');
  const [password, setPassword] = useState('Password123!');
  const [loginError, setLoginError] = useState('');

  // Dashboard Data State
  const [metrics, setMetrics] = useState<any>(null);
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [providers, setProviders] = useState<ProviderHealth[]>([]);
  const [wsStatus, setWsStatus] = useState<'connected' | 'disconnected'>('disconnected');

  // Selected Detail State
  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [iocSearch, setIocSearch] = useState('');
  const [iocResult, setIocResult] = useState<any>(null);
  const [triageComment, setTriageComment] = useState('');

  // Ingestion State
  const [ingestFile, setIngestFile] = useState<File | null>(null);
  const [ingestStatus, setIngestStatus] = useState<string>('');

  // Admin / User Creation State
  const [usersList, setUsersList] = useState<any[]>([]);
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
    try {
      const res = await api.login(email, password);
      setAuthToken(res.access_token);
      const u = await api.getMe();
      setUser(u);
    } catch (err: any) {
      setLoginError(err.message || 'Login failed');
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
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/notifications`;
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
      setIngestStatus(`File queued successfully! Task ID: ${res.task_id}`);
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

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-950 text-slate-300">
        <div className="text-xl font-mono animate-pulse">Initializing CyberShield-AI-SOC Security Center...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-950 p-4">
        <div className="glass-panel w-full max-w-md p-8 shadow-2xl">
          <div className="flex items-center justify-center mb-6">
            <div className="h-10 w-10 rounded-lg bg-emerald-500/20 border border-emerald-500/50 flex items-center justify-center text-emerald-400 font-bold text-xl mr-3">
              🛡️
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wide">CyberShield-AI-SOC</h1>
          </div>
          <p className="text-sm text-slate-400 text-center mb-6">Autonomous Email Ingestion & Threat Analysis Center</p>

          {loginError && (
            <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/40 rounded text-rose-400 text-sm">
              {loginError}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-900/80 border border-slate-700/80 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-900/80 border border-slate-700/80 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <button
              type="submit"
              className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded shadow transition"
            >
              Sign In to SOC Center
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur px-6 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <span className="text-2xl">🛡️</span>
            <span className="font-bold text-lg text-white">CyberShield-AI-SOC</span>
          </div>
          <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            v0.1.0-alpha
          </span>
          <div className="flex items-center space-x-2 text-xs text-slate-400">
            <span className={`h-2 w-2 rounded-full ${wsStatus === 'connected' ? 'bg-emerald-400 animate-ping' : 'bg-rose-500'}`} />
            <span>{wsStatus === 'connected' ? 'Live Telemetry' : 'Offline'}</span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-right">
            <div className="text-sm font-medium text-white">{user.email}</div>
            <div className="text-xs text-slate-400">{user.role}</div>
          </div>
          <button
            onClick={handleLogout}
            className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700"
          >
            Logout
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-slate-900/30 border-b border-slate-800/60 px-6 flex space-x-1">
        {[
          { id: 'dashboard', label: '📊 Dashboard Overview' },
          { id: 'alerts', label: `🚨 Threat Alerts (${alerts.length})` },
          { id: 'cases', label: `📁 SOC Cases (${cases.length})` },
          { id: 'threat_intel', label: '🔍 IOC & Threat Intel' },
          { id: 'tasks', label: '⚙️ Async Pipeline Tasks' },
          { id: 'analytics', label: '📈 Threat Analytics & Reports' },
          { id: 'admin', label: '🔒 Administration & Settings' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-3 text-sm font-medium transition border-b-2 ${
              activeTab === tab.id
                ? 'border-emerald-500 text-emerald-400 bg-emerald-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Quick Ingest Bar */}
        <section className="glass-panel p-4 flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-white text-sm">Async RFC822 EML Ingestion</h3>
            <p className="text-xs text-slate-400">Upload a suspicious .eml email file to trigger Celery analysis pipeline.</p>
          </div>
          <form onSubmit={handleIngest} className="flex items-center space-x-3">
            <input
              type="file"
              accept=".eml"
              onChange={(e) => setIngestFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-emerald-400 hover:file:bg-slate-700"
            />
            <button
              type="submit"
              disabled={!ingestFile}
              className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold rounded shadow transition"
            >
              Upload & Process
            </button>
          </form>
          {ingestStatus && <div className="text-xs font-mono text-emerald-400">{ingestStatus}</div>}
        </section>

        {/* 1. Dashboard Overview */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="glass-panel p-5 border-l-4 border-emerald-500">
                <div className="text-xs text-slate-400 uppercase font-semibold">Processed Today</div>
                <div className="text-3xl font-bold text-white mt-1">
                  {metrics?.statistics?.total_processed_today || 0}
                </div>
              </div>
              <div className="glass-panel p-5 border-l-4 border-amber-500">
                <div className="text-xs text-slate-400 uppercase font-semibold">Unresolved Threat Alerts</div>
                <div className="text-3xl font-bold text-amber-400 mt-1">
                  {metrics?.statistics?.unresolved_alerts_count || 0}
                </div>
              </div>
              <div className="glass-panel p-5 border-l-4 border-rose-500">
                <div className="text-xs text-slate-400 uppercase font-semibold">Quarantined Threats</div>
                <div className="text-3xl font-bold text-rose-400 mt-1">
                  {metrics?.statistics?.quarantined_today || 0}
                </div>
              </div>
              <div className="glass-panel p-5 border-l-4 border-blue-500">
                <div className="text-xs text-slate-400 uppercase font-semibold">Active SOC Cases</div>
                <div className="text-3xl font-bold text-blue-400 mt-1">{cases.length}</div>
              </div>
            </div>

            {/* Recent High-Risk Alerts Table */}
            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-4">Recent High-Risk Threat Alerts</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3">Sender</th>
                      <th className="p-3">Subject</th>
                      <th className="p-3">Risk Score</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {alerts.slice(0, 5).map((a) => (
                      <tr key={a.id} className="hover:bg-slate-900/40">
                        <td className="p-3 font-mono text-slate-300">{a.sender}</td>
                        <td className="p-3 text-slate-200">{a.subject || 'No Subject'}</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded font-mono font-bold ${
                              a.risk_score >= 0.8
                                ? 'badge-critical'
                                : a.risk_score >= 0.5
                                ? 'badge-high'
                                : 'badge-low'
                            }`}
                          >
                            {(a.risk_score * 100).toFixed(0)}%
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {a.status}
                          </span>
                        </td>
                        <td className="p-3">
                          <button
                            onClick={() => handleInspectAlert(a.id)}
                            className="px-3 py-1 bg-emerald-600/80 hover:bg-emerald-500 text-white rounded text-xs"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 2. Alerts View */}
        {activeTab === 'alerts' && (
          <div className="glass-panel p-6 space-y-4">
            <h3 className="font-bold text-lg text-white">Threat Alert Queue & Triage</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 uppercase font-mono border-b border-slate-800">
                  <tr>
                    <th className="p-3">Alert ID</th>
                    <th className="p-3">Sender</th>
                    <th className="p-3">Subject</th>
                    <th className="p-3">Risk Score</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {alerts.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-900/40">
                      <td className="p-3 font-mono text-slate-400">{a.id.slice(0, 8)}...</td>
                      <td className="p-3 font-mono text-slate-300">{a.sender}</td>
                      <td className="p-3 text-slate-200">{a.subject}</td>
                      <td className="p-3">
                        <span className="font-bold text-rose-400 font-mono">{(a.risk_score * 100).toFixed(0)}%</span>
                      </td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {a.status}
                        </span>
                      </td>
                      <td className="p-3">
                        <button
                          onClick={() => handleInspectAlert(a.id)}
                          className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs"
                        >
                          Inspect & Triage
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 3. Cases View */}
        {activeTab === 'cases' && (
          <div className="space-y-6">
            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-4">Create New Incident Case</h3>
              <form onSubmit={handleCreateCase} className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <input
                  type="text"
                  placeholder="Case Title"
                  required
                  value={newCaseTitle}
                  onChange={(e) => setNewCaseTitle(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                />
                <select
                  value={newCaseSeverity}
                  onChange={(e) => setNewCaseSeverity(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                >
                  <option value="Critical">Critical Severity</option>
                  <option value="High">High Severity</option>
                  <option value="Medium">Medium Severity</option>
                  <option value="Low">Low Severity</option>
                </select>
                <button
                  type="submit"
                  className="py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded"
                >
                  Open Incident Case
                </button>
              </form>
            </div>

            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-4">SOC Incident Cases</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3">Case ID</th>
                      <th className="p-3">Title</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {cases.map((c) => (
                      <tr key={c.id} className="hover:bg-slate-900/40">
                        <td className="p-3 font-mono text-slate-400">{c.id.slice(0, 8)}...</td>
                        <td className="p-3 text-slate-200 font-medium">{c.title}</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded ${
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
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">{c.status}</span>
                        </td>
                        <td className="p-3">
                          <button
                            onClick={() => handleInspectCase(c.id)}
                            className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs"
                          >
                            Investigate
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 4. Threat Intel View */}
        {activeTab === 'threat_intel' && (
          <div className="space-y-6">
            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-2">IOC Threat Intelligence Explorer</h3>
              <p className="text-xs text-slate-400 mb-4">Search URLs, domains, IP addresses, hashes (MD5/SHA256), or emails across VirusTotal, AbuseIPDB, URLHaus, OTX, OpenPhish.</p>
              <form onSubmit={handleSearchIOC} className="flex space-x-3">
                <input
                  type="text"
                  placeholder="Enter IOC (e.g. http://phish-site.com/login or 192.168.1.1)"
                  required
                  value={iocSearch}
                  onChange={(e) => setIocSearch(e.target.value)}
                  className="flex-1 bg-slate-900 border border-slate-700 rounded px-4 py-2 text-xs text-white"
                />
                <button
                  type="submit"
                  className="px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded"
                >
                  Enrich IOC
                </button>
              </form>

              {iocResult && (
                <div className="mt-6 p-4 bg-slate-900/90 rounded border border-slate-800 space-y-3 font-mono text-xs">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-200">Indicator: {iocResult.ioc}</span>
                    <span className={`px-2 py-0.5 rounded uppercase font-bold ${iocResult.overall_verdict === 'malicious' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-400'}`}>
                      Verdict: {iocResult.overall_verdict}
                    </span>
                  </div>
                  <div>Confidence: {(iocResult.overall_confidence * 100).toFixed(0)}%</div>
                  <div>Confirming Providers: {iocResult.confirming_malicious_providers}</div>
                  <div>Tags: {iocResult.tags?.join(', ') || 'None'}</div>
                </div>
              )}
            </div>

            {/* Provider Health Monitor */}
            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-4">Threat Intelligence Provider Health</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {providers.map((p) => (
                  <div key={p.provider} className="glass-card p-4 space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-white uppercase text-xs">{p.provider}</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${p.health === 'HEALTHY' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}`}>
                        {p.health}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400">Circuit State: {p.circuit_state}</div>
                    <div className="text-xs text-slate-400">Total Requests: {p.total_requests}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* 5. Live Tasks View */}
        {activeTab === 'tasks' && (
          <div className="glass-panel p-6 space-y-4">
            <h3 className="font-bold text-lg text-white">Live Asynchronous Pipeline Tasks</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-900/80 text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="p-3">Task ID</th>
                    <th className="p-3">Type</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Retries</th>
                    <th className="p-3">Created At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {tasks.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-900/40">
                      <td className="p-3 text-slate-300">{t.id.slice(0, 12)}...</td>
                      <td className="p-3 text-slate-400">{t.task_type}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded ${t.status === 'Completed' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}`}>
                          {t.status}
                        </span>
                      </td>
                      <td className="p-3 text-slate-400">{t.retry_count}</td>
                      <td className="p-3 text-slate-500">{t.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 6. Analytics & Reports View */}
        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-4">Executive Threat Analytics & PDF Report Generation</h3>
              <p className="text-xs text-slate-400 mb-4">Export executive summary reports or case investigation writeups.</p>
              <button
                onClick={async () => {
                  const summary = await api.getCaseReportText(cases[0]?.id || '');
                  const blob = new Blob([summary], { type: 'text/plain' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = 'executive_soc_summary_report.txt';
                  a.click();
                }}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded"
              >
                Export Executive Threat Summary (.txt/.pdf)
              </button>
            </div>
          </div>
        )}

        {/* 7. Admin View */}
        {activeTab === 'admin' && (
          <div className="space-y-6">
            <div className="glass-panel p-6">
              <h3 className="font-bold text-lg text-white mb-4">System Settings & Detection Thresholds</h3>
              <form onSubmit={handleUpdateSettings} className="space-y-4 max-w-md">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-1">AI Detection Confidence Threshold</label>
                  <input
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={confidenceThreshold}
                    onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                  />
                </div>
                <button type="submit" className="px-4 py-2 bg-emerald-600 text-white text-xs font-semibold rounded">
                  Update Detection Threshold
                </button>
              </form>
            </div>

            {user.role === 'Admin' && (
              <div className="glass-panel p-6">
                <h3 className="font-bold text-lg text-white mb-4">User Administration</h3>
                <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-6">
                  <input
                    type="email"
                    placeholder="New User Email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                  />
                  <input
                    type="password"
                    placeholder="Password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                  />
                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value)}
                    className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                  >
                    <option value="Analyst_L1">Analyst_L1</option>
                    <option value="Analyst_L2">Analyst_L2</option>
                    <option value="Admin">Admin</option>
                  </select>
                  <button type="submit" className="py-2 bg-emerald-600 text-white text-xs font-semibold rounded">
                    Create User
                  </button>
                </form>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/80 text-slate-400 uppercase">
                      <tr>
                        <th className="p-2">User Email</th>
                        <th className="p-2">Role</th>
                        <th className="p-2">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {usersList.map((u) => (
                        <tr key={u.id}>
                          <td className="p-2 text-slate-300">{u.email}</td>
                          <td className="p-2 text-slate-400">{u.role}</td>
                          <td className="p-2 text-emerald-400">{u.is_active ? 'Active' : 'Inactive'}</td>
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

      {/* Alert Inspection Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur flex items-center justify-center p-4 z-50">
          <div className="glass-panel w-full max-w-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="font-bold text-lg text-white">Alert Detail Breakdown</h3>
              <button onClick={() => setSelectedAlert(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="space-y-2 text-xs">
              <div><span className="font-semibold text-slate-400">Sender:</span> <span className="font-mono text-slate-200">{selectedAlert.email?.sender}</span></div>
              <div><span className="font-semibold text-slate-400">Subject:</span> <span className="text-slate-200">{selectedAlert.email?.subject}</span></div>
              <div><span className="font-semibold text-slate-400">Risk Score:</span> <span className="font-bold text-rose-400 font-mono">{(selectedAlert.risk_score * 100).toFixed(0)}%</span></div>
              <div><span className="font-semibold text-slate-400">Current Status:</span> <span className="text-slate-200">{selectedAlert.status}</span></div>

              {selectedAlert.ai_analysis && (
                <div className="p-3 bg-slate-900 rounded border border-slate-800 space-y-1">
                  <div className="font-semibold text-emerald-400">AI Threat Analysis:</div>
                  <div>Phishing Probability: {(selectedAlert.ai_analysis.phishing_probability * 100).toFixed(1)}%</div>
                  <div>Critical Threat Tokens: {selectedAlert.ai_analysis.critical_tokens?.join(', ') || 'None'}</div>
                </div>
              )}

              <div className="pt-3 border-t border-slate-800 space-y-2">
                <label className="block font-semibold text-slate-400">Triage Comments</label>
                <input
                  type="text"
                  placeholder="Enter investigation comments..."
                  value={triageComment}
                  onChange={(e) => setTriageComment(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white"
                />
                <div className="flex space-x-2 pt-2">
                  <button
                    onClick={() => handleTriageAlert('RESOLVED_QUARANTINED')}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold"
                  >
                    Quarantine Email
                  </button>
                  <button
                    onClick={() => handleTriageAlert('RESOLVED_FALSE_POSITIVE')}
                    className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-xs font-semibold"
                  >
                    Mark False Positive
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Case Inspection Modal */}
      {selectedCase && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur flex items-center justify-center p-4 z-50">
          <div className="glass-panel w-full max-w-3xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="font-bold text-lg text-white">Case Investigation: {selectedCase.title}</h3>
              <button onClick={() => setSelectedCase(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="space-y-4 text-xs">
              <div className="flex space-x-4">
                <span>Severity: <strong className="text-rose-400">{selectedCase.severity}</strong></span>
                <span>Status: <strong>{selectedCase.status}</strong></span>
              </div>

              <div>
                <h4 className="font-bold text-slate-300 mb-2">Analyst Investigation Notes</h4>
                <div className="space-y-2 mb-3 max-h-40 overflow-y-auto">
                  {selectedCase.notes?.map((n: any) => (
                    <div key={n.id} className="p-2 bg-slate-900 rounded border border-slate-800 text-slate-300">
                      <div>{n.content}</div>
                      <div className="text-[10px] text-slate-500 mt-1">{n.created_at}</div>
                    </div>
                  ))}
                </div>
                <form onSubmit={handleAddNote} className="flex space-x-2">
                  <input
                    type="text"
                    placeholder="Add investigation note..."
                    required
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                    className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
                  />
                  <button type="submit" className="px-4 py-1.5 bg-emerald-600 text-white rounded text-xs font-semibold">
                    Add Note
                  </button>
                </form>
              </div>

              <div>
                <h4 className="font-bold text-slate-300 mb-2">Incident Timeline & Audit Trail</h4>
                <div className="space-y-1.5 font-mono max-h-40 overflow-y-auto">
                  {selectedCase.timeline?.map((ev: any) => (
                    <div key={ev.id} className="text-slate-400 border-l-2 border-emerald-500 pl-3 py-1">
                      <span className="text-slate-200 font-semibold">{ev.event_type}:</span> {ev.description}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

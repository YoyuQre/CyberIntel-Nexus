/**
 * Dashboard.jsx — CyberIntel Nexus SOC Dashboard
 * ================================================
 * Premium dark-mode Security Operations Center interface for the
 * CyberIntel Nexus threat intelligence pipeline.
 *
 * Architecture:
 *   - Google OAuth2 sign-in via @react-oauth/google
 *   - JWT stored in React state only (never localStorage)
 *   - All API calls include: Authorization: Bearer <jwt>
 *   - Polling /state every 4 s (cleaned up on unmount / session change)
 *   - HITL section only rendered during staging/awaiting-approval phase
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { googleLogout } from '@react-oauth/google'
import {
  Shield, Activity, AlertTriangle, CheckCircle, XCircle,
  Clock, Send, RefreshCw, LogOut, FileText, Eye,
  ChevronRight, Zap, Lock, Server, Terminal,
  ThumbsUp, ThumbsDown, User, Cpu, Radio, UploadCloud
} from 'lucide-react'
import LoginScreen from './Login'

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080'
const POLL_INTERVAL_MS = 4000
const STAGING_PHASES = new Set(['staging'])

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function phaseColor(phase) {
  const map = {
    ingest:    'text-cyber-cyan',
    parse:     'text-cyber-blue',
    generate:  'text-cyber-purple',
    validate:  'text-cyber-amber',
    staging:   'text-cyber-amber',
    commit:    'text-cyber-green',
    completed: 'text-cyber-green',
    error:     'text-cyber-red',
    containment: 'text-cyber-red',
  }
  return map[phase] ?? 'text-cyber-muted'
}

function phaseBadge(phase) {
  const map = {
    staging:   'bg-amber-500/15 text-amber-400 border border-amber-500/30',
    completed: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
    error:     'bg-red-500/15 text-red-400 border border-red-500/30',
    containment: 'bg-red-500/15 text-red-400 border border-red-500/30',
  }
  return map[phase] ?? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
}

function phaseIcon(phase) {
  const iconClass = 'w-3.5 h-3.5'
  const icons = {
    staging:   <Clock    className={iconClass} />,
    completed: <CheckCircle className={iconClass} />,
    error:     <XCircle  className={iconClass} />,
    containment: <XCircle className={iconClass} />,
  }
  return icons[phase] ?? <Activity className={iconClass} />
}

async function apiFetch(path, token, options = {}) {
  const resp = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`)
  return data
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function PulsingDot({ color = 'bg-cyber-green' }) {
  return (
    <span className="relative flex h-2.5 w-2.5">
      <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${color} opacity-60`} />
      <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${color}`} />
    </span>
  )
}

function StatCard({ icon: Icon, label, value, color = 'text-cyber-blue', sub }) {
  return (
    <div className="glass-card p-5 flex items-start gap-4 hover:border-cyber-blue/40 transition-colors duration-200">
      <div className={`p-2.5 rounded-lg bg-cyber-surface ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="min-w-0">
        <p className="text-xs text-cyber-muted font-medium uppercase tracking-widest">{label}</p>
        <p className={`stat-value ${color} mt-0.5`}>{value}</p>
        {sub && <p className="text-xs text-cyber-muted mt-0.5 truncate">{sub}</p>}
      </div>
    </div>
  )
}

function RuleCard({ rule, index }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="glass-card overflow-hidden hover:border-cyber-blue/40 transition-all duration-200 animate-fade-in">
      <button
        id={`rule-${rule.id || index}`}
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-cyber-surface/50 transition-colors"
      >
        <div className="p-2 bg-cyber-purple/10 rounded-lg border border-cyber-purple/20">
          <FileText className="w-4 h-4 text-cyber-purple" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-sm text-cyber-text truncate">
              {rule.rule_name || `Rule #${index + 1}`}
            </span>
            <span className="status-badge bg-purple-500/10 text-purple-400 border border-purple-500/20 shrink-0">
              {rule.rule_type || 'unknown'}
            </span>
          </div>
          <span className="text-xs text-cyber-muted">{rule.target_platform || 'generic'}</span>
        </div>
        <ChevronRight className={`w-4 h-4 text-cyber-muted transition-transform duration-200 shrink-0 ${expanded ? 'rotate-90' : ''}`} />
      </button>
      {expanded && (
        <div className="px-4 pb-4 animate-slide-in">
          <pre className="code-block">{rule.rule_content || rule.content || JSON.stringify(rule, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}

function PhaseTimeline({ phase }) {
  const steps = ['ingest', 'parse', 'generate', 'validate', 'staging', 'completed']
  const currentIdx = steps.indexOf(phase)
  if (phase === 'error' || phase === 'containment') {
    return (
      <div className="flex items-center gap-2 text-cyber-red text-sm">
        <XCircle className="w-4 h-4" />
        <span className="font-mono">Pipeline terminated — containment active</span>
      </div>
    )
  }
  return (
    <div className="flex items-center gap-0 flex-wrap">
      {steps.map((s, i) => {
        const done    = i < currentIdx
        const current = i === currentIdx
        return (
          <div key={s} className="flex items-center">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono transition-all
              ${current ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 font-semibold' :
                done    ? 'text-cyber-green' : 'text-cyber-muted'}`}>
              {done    ? <CheckCircle className="w-3 h-3" /> :
               current ? <PulsingDot color="bg-cyber-blue" /> :
                         <span className="w-3 h-3 rounded-full border border-current inline-block" />}
              {s}
            </div>
            {i < steps.length - 1 && (
              <ChevronRight className={`w-3 h-3 mx-0.5 ${done ? 'text-cyber-green' : 'text-cyber-border'}`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// HITL Review Panel
// ---------------------------------------------------------------------------
function HitlPanel({ session, token, user, onDecision }) {
  const [notes, setNotes] = useState('')
  const [loading, setLoading] = useState(null) // 'approve' | 'reject' | null
  const [error, setError] = useState(null)

  const submit = async (action) => {
    if (action === 'Reject' && !notes.trim()) {
      setError('Please provide a rejection reason in the notes field.')
      return
    }
    setError(null)
    setLoading(action)
    try {
      const result = await apiFetch('/resume-staging', token, {
        method: 'POST',
        body: JSON.stringify({
          session_id: session.session_id,
          action,
          notes: notes.trim(),
        }),
      })
      onDecision(result)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(null)
    }
  }

  return (
    <div id="hitl-panel" className="glass-card overflow-hidden glow-amber animate-slide-in">
      {/* Header */}
      <div className="flex items-center gap-3 px-5 py-4 bg-amber-500/5 border-b border-amber-500/20">
        <div className="p-2 bg-amber-500/10 rounded-lg border border-amber-500/20">
          <Lock className="w-5 h-5 text-cyber-amber" />
        </div>
        <div>
          <h2 className="font-bold text-cyber-amber">Human-in-the-Loop Review Gate</h2>
          <p className="text-xs text-amber-400/70">
            {session.rule_artifacts?.length || 0} rule artifact(s) pending mandatory approval before deployment
          </p>
        </div>
        <div className="ml-auto">
          <PulsingDot color="bg-amber-400" />
        </div>
      </div>

      {/* Rule artifacts */}
      <div className="p-5 space-y-3">
        <h3 className="text-sm font-semibold text-cyber-muted uppercase tracking-widest flex items-center gap-2">
          <Eye className="w-3.5 h-3.5" /> Generated Artifacts — Expand to Review
        </h3>
        {(session.rule_artifacts || []).map((rule, i) => (
          <RuleCard key={rule.id || i} rule={rule} index={i} />
        ))}

        {/* Reviewer notes */}
        <div className="mt-4">
          <label className="block text-sm font-medium text-cyber-muted mb-2">
            Reviewer Notes <span className="text-cyber-red">*</span>{' '}
            <span className="text-xs font-normal">(required for rejection; recommended for approval)</span>
          </label>
          <textarea
            id="reviewer-notes"
            rows={3}
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder="Enter your review findings, justification, or rejection rationale…"
            className="input-field"
          />
        </div>

        {error && (
          <div className="flex items-center gap-2 text-cyber-red text-sm bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        {/* Action buttons */}
        {user?.auth_provider === 'google' ? (
          <div>
            <div className="flex gap-3 pt-2">
              <button
                id="btn-approve"
                onClick={() => submit('Approve')}
                disabled={!!loading}
                className="btn-approve flex-1 flex items-center justify-center gap-2"
              >
                {loading === 'Approve' ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <ThumbsUp className="w-4 h-4" />
                )}
                {loading === 'Approve' ? 'Approving…' : 'Approve & Deploy'}
              </button>
              <button
                id="btn-reject"
                onClick={() => submit('Reject')}
                disabled={!!loading}
                className="btn-reject flex-1 flex items-center justify-center gap-2"
              >
                {loading === 'Reject' ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <ThumbsDown className="w-4 h-4" />
                )}
                {loading === 'Reject' ? 'Rejecting…' : 'Reject & Quarantine'}
              </button>
            </div>
            <p className="text-xs text-cyber-muted text-center pt-1 mt-2">
              <Lock className="w-3 h-3 inline mr-1" />
              Decision is cryptographically attributed to your verified Google identity — action cannot be undone.
            </p>
          </div>
        ) : (
          <div className="mt-4 p-4 rounded-lg bg-cyber-surface border border-cyber-border text-center text-sm text-cyber-muted">
            <Lock className="w-5 h-5 mx-auto mb-2 opacity-50" />
            <p>Only authorized Google Workspace identities can approve or reject staging deployments.</p>
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Outcome Banner
// ---------------------------------------------------------------------------
function OutcomeBanner({ session }) {
  const phase = session.current_phase
  const staging = session.staging || {}

  if (phase === 'completed') {
    return (
      <div id="outcome-commit" className="glass-card p-5 border-emerald-500/40 glow-green animate-fade-in">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
            <CheckCircle className="w-6 h-6 text-cyber-green" />
          </div>
          <div>
            <h3 className="font-bold text-cyber-green text-lg">COMMIT SUCCESS</h3>
            <p className="text-xs text-emerald-400/70">
              Rules deployed · commit <span className="font-mono">{staging.commit_id?.slice(0,12) || '—'}</span>
              · approved by <span className="font-mono text-cyber-text">{staging.reviewer_id || '—'}</span>
            </p>
          </div>
        </div>
        {staging.commit_receipts?.length > 0 && (
          <div className="mt-3 space-y-1.5">
            {staging.commit_receipts.map((r, i) => (
              <div key={i} className="flex items-center gap-2 text-xs font-mono text-cyber-muted bg-cyber-bg rounded px-3 py-1.5 border border-cyber-border">
                <CheckCircle className="w-3 h-3 text-cyber-green shrink-0" />
                <span className="text-cyber-text">{r.rule_name}</span>
                <span>→</span>
                <span className="text-cyber-cyan">{r.platform}</span>
                <span className="ml-auto text-cyber-green">{r.status}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  if (phase === 'error' || phase === 'containment') {
    return (
      <div id="outcome-containment" className="glass-card p-5 border-red-500/40 glow-red animate-fade-in">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-red-500/10 rounded-xl border border-red-500/30">
            <XCircle className="w-6 h-6 text-cyber-red" />
          </div>
          <div>
            <h3 className="font-bold text-cyber-red text-lg">CONTAINMENT — QUARANTINED</h3>
            <p className="text-xs text-red-400/70">
              Artifacts quarantined · ID <span className="font-mono">{staging.containment_id?.slice(0,12) || '—'}</span>
            </p>
            {staging.rejection_reason && (
              <p className="text-xs text-cyber-muted mt-1">Reason: {staging.rejection_reason}</p>
            )}
          </div>
        </div>
      </div>
    )
  }

  return null
}



// ---------------------------------------------------------------------------
// Main Dashboard
// ---------------------------------------------------------------------------
export default function Dashboard() {
  // ── Auth state ────────────────────────────────────────────────────────────
  const [jwt, setJwt]       = useState(null)   // raw Google credential JWT
  const [user, setUser]     = useState(null)   // { email, name, picture }

  // ── Session state ─────────────────────────────────────────────────────────
  const [sessions, setSessions] = useState([]) // [{session_id, ...state}]
  const [activeIdx, setActiveIdx] = useState(0)

  // ── Ingestion form ────────────────────────────────────────────────────────
  const [intelText, setIntelText] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)
  const fileInputRef = useRef(null)
  const [ingesting, setIngesting] = useState(false)
  const [ingestError, setIngestError] = useState(null)

  // ── Polling ───────────────────────────────────────────────────────────────
  const pollRef = useRef(null)

  const activeSession = sessions[activeIdx] || null

  // ── Decode Google credential → user info ─────────────────────────────────
  const handleLoginSuccess = useCallback((token) => {
    setJwt(token)
    // Decode JWT payload (base64url)
    try {
      const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
      setUser({ 
        email: payload.sub || payload.email, 
        name: payload.name || payload.email, 
        picture: payload.picture,
        auth_provider: payload.iss?.includes('google') ? 'google' : 'local'
      })
    } catch {
      setUser({ email: 'unknown', name: 'User', picture: null, auth_provider: 'local' })
    }
  }, [])

  const handleLogout = useCallback(() => {
    googleLogout()
    setJwt(null)
    setUser(null)
    setSessions([])
    setActiveIdx(0)
    clearInterval(pollRef.current)
  }, [])

  // ── Poll /state for active session ───────────────────────────────────────
  const pollState = useCallback(async (sessionId, token) => {
    try {
      const data = await apiFetch(`/state?session_id=${sessionId}`, token)
      setSessions(prev => prev.map(s =>
        s.session_id === sessionId ? { ...s, ...data } : s
      ))
    } catch {
      // ignore transient poll errors
    }
  }, [])

  useEffect(() => {
    clearInterval(pollRef.current)
    if (!activeSession || !jwt) return
    const { session_id, current_phase } = activeSession
    // Only poll if pipeline is still running
    const terminal = new Set(['completed', 'error', 'containment'])
    if (terminal.has(current_phase)) return
    pollRef.current = setInterval(() => {
      pollState(session_id, jwt)
    }, POLL_INTERVAL_MS)
    return () => clearInterval(pollRef.current)
  }, [activeSession?.session_id, activeSession?.current_phase, jwt, pollState])

  // ── Ingest handler ────────────────────────────────────────────────────────
  const handleIngest = async () => {
    if (!intelText.trim()) return
    setIngesting(true)
    setIngestError(null)
    try {
      const data = await apiFetch('/ingest', jwt, {
        method: 'POST',
        body: JSON.stringify({ raw_threat_intel: intelText.trim() }),
      })
      // Immediately fetch full state
      const state = await apiFetch(`/state?session_id=${data.session_id}`, jwt)
      const newSession = { session_id: data.session_id, ...state }
      setSessions(prev => [newSession, ...prev])
      setActiveIdx(0)
      setIntelText('')
      setSelectedFile(null)
    } catch (e) {
      setIngestError(e.message)
    } finally {
      setIngesting(false)
    }
  }

  // ── HITL decision callback ────────────────────────────────────────────────
  const handleDecision = useCallback((result) => {
    setSessions(prev => prev.map(s =>
      s.session_id === result.session_id ? { ...s, ...result } : s
    ))
    clearInterval(pollRef.current)
  }, [])

  // ── Render: not logged in ─────────────────────────────────────────────────
  if (!jwt || !user) {
    return <LoginScreen onLoginSuccess={handleLoginSuccess} />
  }

  // ── Compute stats ─────────────────────────────────────────────────────────
  const totalSessions  = sessions.length
  const stagingSessions = sessions.filter(s => STAGING_PHASES.has(s.current_phase)).length
  const committed      = sessions.filter(s => s.current_phase === 'completed').length
  const quarantined    = sessions.filter(s => s.current_phase === 'error' || s.current_phase === 'containment').length

  // ── Render: main dashboard ────────────────────────────────────────────────
  return (
    <div className="min-h-screen flex flex-col">
      {/* ── NAV ────────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-cyber-border bg-cyber-bg/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-5 py-3 flex items-center gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-cyber-blue/10 rounded-lg border border-cyber-blue/20">
              <Shield className="w-5 h-5 text-cyber-blue" />
            </div>
            <div>
              <span className="font-extrabold text-cyber-text tracking-tight">CyberIntel</span>
              <span className="font-extrabold text-cyber-blue tracking-tight"> Nexus</span>
            </div>
          </div>

          {/* Live indicator */}
          <div className="flex items-center gap-1.5 ml-1">
            <PulsingDot color="bg-cyber-green" />
            <span className="text-xs text-cyber-green font-mono font-medium">LIVE</span>
          </div>

          <div className="flex-1" />

          {/* Session selector (if multiple) */}
          {sessions.length > 1 && (
            <select
              id="session-selector"
              value={activeIdx}
              onChange={e => setActiveIdx(Number(e.target.value))}
              className="bg-cyber-surface border border-cyber-border rounded-lg px-3 py-1.5 text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-blue"
            >
              {sessions.map((s, i) => (
                <option key={s.session_id} value={i}>
                  Session {i + 1} · {s.current_phase}
                </option>
              ))}
            </select>
          )}

          {/* User info */}
          <div className="flex items-center gap-2.5 pl-4 border-l border-cyber-border">
            {user.picture ? (
              <img src={user.picture} alt={user.name} className="w-8 h-8 rounded-full border border-cyber-border" />
            ) : (
              <div className="w-8 h-8 rounded-full bg-cyber-surface border border-cyber-border flex items-center justify-center">
                <User className="w-4 h-4 text-cyber-muted" />
              </div>
            )}
            <div className="hidden sm:block">
              <p className="text-xs font-semibold text-cyber-text leading-tight">{user.name}</p>
              <p className="text-xs text-cyber-muted leading-tight">{user.email}</p>
            </div>
            <button
              id="btn-logout"
              onClick={handleLogout}
              className="p-2 hover:bg-cyber-surface rounded-lg transition-colors text-cyber-muted hover:text-cyber-red"
              title="Sign out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* ── MAIN ───────────────────────────────────────────────────────────── */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-5 py-7 space-y-6">

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard icon={Radio}        label="Sessions"   value={totalSessions}  color="text-cyber-cyan"   />
          <StatCard icon={Clock}        label="Pending"    value={stagingSessions} color="text-cyber-amber"  />
          <StatCard icon={CheckCircle}  label="Committed"  value={committed}      color="text-cyber-green"  />
          <StatCard icon={AlertTriangle} label="Quarantined" value={quarantined}  color="text-cyber-red"    />
        </div>

        {/* ── INGESTION FORM ─────────────────────────────────────────────── */}
        <div className="glass-card p-5">
          <h2 className="flex items-center gap-2 text-sm font-bold text-cyber-text uppercase tracking-widest mb-4">
            <Terminal className="w-4 h-4 text-cyber-blue" />
            Threat Intelligence Ingestion
          </h2>
          <textarea
            id="intel-input"
            rows={5}
            value={intelText}
            onChange={e => setIntelText(e.target.value)}
            placeholder={`Paste raw threat intelligence here…\n\nExample:\n  Observed C2 traffic to 198.51.100.42 and domain evil-c2.io. Hash: 4e99506...`}
            className="input-field mb-3"
          />
          <div className="flex items-center gap-3 mb-3">
             <input 
               type="file" 
               ref={fileInputRef} 
               onChange={(e) => {
                 const file = e.target.files[0];
                 if (file) {
                   const reader = new FileReader();
                   reader.onload = (e) => setIntelText(e.target.result);
                   reader.readAsText(file);
                   setSelectedFile(file);
                 }
               }} 
               className="hidden" 
               accept=".txt,.csv,.json" 
             />
             <button 
               onClick={() => fileInputRef.current.click()} 
               className="flex items-center gap-2 px-3 py-1.5 text-xs text-cyber-muted bg-cyber-surface rounded border border-cyber-border hover:bg-cyber-blue/10 transition-colors"
             >
               <UploadCloud className="w-4 h-4" /> {selectedFile ? selectedFile.name : 'Upload File'}
             </button>
             {selectedFile && (
               <button onClick={() => { setSelectedFile(null); setIntelText(''); }} className="text-xs text-cyber-red hover:underline">
                 Clear
               </button>
             )}
          </div>
          {ingestError && (
            <div className="flex items-center gap-2 text-cyber-red text-sm bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3 mb-3">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {ingestError}
            </div>
          )}
          <button
            id="btn-ingest"
            onClick={handleIngest}
            disabled={ingesting || !intelText.trim()}
            className="btn-primary flex items-center gap-2"
          >
            {ingesting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            {ingesting ? 'Running pipeline…' : 'Submit Threat Report'}
          </button>
          <p className="text-xs text-cyber-muted mt-2">
            Signed in as <span className="text-cyber-text font-mono">{user.email}</span> — you will be the session creator.
          </p>
        </div>

        {/* ── ACTIVE SESSION ─────────────────────────────────────────────── */}
        {activeSession && (
          <div className="space-y-4 animate-fade-in">
            {/* Phase timeline */}
            <div className="glass-card p-4">
              <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`status-badge ${phaseBadge(activeSession.current_phase)}`}>
                      {phaseIcon(activeSession.current_phase)}
                      {activeSession.current_phase}
                    </span>
                    <span className="text-xs text-cyber-muted font-mono">
                      Session: {activeSession.session_id?.slice(0, 12)}…
                    </span>
                  </div>
                  <p className="text-xs text-cyber-muted mt-1.5 font-mono leading-relaxed max-w-2xl">
                    {activeSession.status_message}
                  </p>
                </div>
                <button
                  id="btn-refresh"
                  onClick={() => pollState(activeSession.session_id, jwt)}
                  className="p-2 hover:bg-cyber-surface rounded-lg transition-colors text-cyber-muted hover:text-cyber-cyan"
                  title="Refresh state"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
              <PhaseTimeline phase={activeSession.current_phase} />
            </div>

            {/* Outcome banners */}
            <OutcomeBanner session={activeSession} />

            {/* HITL gate — only in staging */}
            {STAGING_PHASES.has(activeSession.current_phase) &&
             activeSession.staging?.status === 'pending' && (
              <HitlPanel
                session={activeSession}
                token={jwt}
                user={user}
                onDecision={handleDecision}
              />
            )}

            {/* Rule artifacts list */}
            {activeSession.rule_artifacts?.length > 0 &&
              activeSession.current_phase !== 'staging' && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-widest flex items-center gap-2">
                  <FileText className="w-3.5 h-3.5" />
                  Generated Rule Artifacts ({activeSession.rule_artifacts.length})
                </h3>
                {activeSession.rule_artifacts.map((rule, i) => (
                  <RuleCard key={rule.id || i} rule={rule} index={i} />
                ))}
              </div>
            )}

            {/* Validation errors */}
            {activeSession.validation_errors?.length > 0 && (
              <div className="glass-card p-4 border-red-500/30">
                <h3 className="text-xs font-semibold text-cyber-red uppercase tracking-widest mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Validation Errors ({activeSession.validation_errors.length})
                </h3>
                <div className="space-y-2">
                  {activeSession.validation_errors.map((err, i) => (
                    <div key={i} className="text-xs font-mono bg-cyber-bg border border-red-500/20 rounded px-3 py-2">
                      <span className="text-cyber-red">[{err.error_type || 'ERROR'}]</span>{' '}
                      <span className="text-cyber-muted">{err.error_message}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Empty state */}
        {sessions.length === 0 && (
          <div className="glass-card p-12 text-center">
            <Shield className="w-12 h-12 text-cyber-border mx-auto mb-4" />
            <h3 className="text-cyber-muted font-semibold mb-1">No active sessions</h3>
            <p className="text-xs text-cyber-muted/70 max-w-sm mx-auto">
              Submit a threat intelligence report above to start the AI pipeline.
              The system will automatically ingest, parse, generate detection rules, and queue them for your review.
            </p>
          </div>
        )}

        {/* Previous sessions list */}
        {sessions.length > 1 && (
          <div className="glass-card p-4">
            <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-widest mb-3">
              All Sessions ({sessions.length})
            </h3>
            <div className="space-y-1.5">
              {sessions.map((s, i) => (
                <button
                  key={s.session_id}
                  id={`session-item-${i}`}
                  onClick={() => setActiveIdx(i)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors
                    ${i === activeIdx ? 'bg-cyber-blue/10 border border-cyber-blue/30' : 'hover:bg-cyber-surface border border-transparent'}`}
                >
                  <span className={`status-badge shrink-0 ${phaseBadge(s.current_phase)}`}>
                    {phaseIcon(s.current_phase)}
                    {s.current_phase}
                  </span>
                  <span className="text-xs font-mono text-cyber-muted flex-1 truncate">
                    {s.session_id?.slice(0, 20)}…
                  </span>
                  <span className="text-xs text-cyber-muted shrink-0">
                    {s.rule_artifacts?.length || 0} rules
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-cyber-muted shrink-0" />
                </button>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* ── FOOTER ─────────────────────────────────────────────────────────── */}
      <footer className="border-t border-cyber-border py-4">
        <p className="text-center text-xs text-cyber-muted">
          CyberIntel Nexus · Agents for Business Track ·{' '}
          <span className="font-mono text-cyber-blue/60">LangGraph + Google ADK + FastAPI</span>
        </p>
      </footer>
    </div>
  )
}

/*
================================================================================
WORKFLOW WALKTHROUGH — Sign-in → Submit → Review → Approve
================================================================================

## 1  Sign In

The landing screen is displayed until the user authenticates.

  ┌───────────────────────────────────────────────────────────────┐
  │  🛡  CyberIntel Nexus                                        │
  │                                                               │
  │       [Sign in with Google] ← GoogleLogin component          │
  └───────────────────────────────────────────────────────────────┘

  - Clicking the Google button opens a standard OAuth2 consent dialog.
  - On success, @react-oauth/google returns a credential (raw JWT).
  - The JWT is stored in React state ONLY — never written to localStorage
    or cookies.
  - The JWT payload is decoded client-side only for display purposes
    (name, email, picture). Actual verification happens server-side on
    every authenticated API call.

## 2  Submit Threat Intelligence

Once signed in, the Ingestion panel is visible:

  ┌───────────────────────────────────────────────────────────────┐
  │  📡 Threat Intelligence Ingestion                             │
  │                                                               │
  │  [textarea] — paste raw IOC text here                         │
  │                                                               │
  │  [Submit Threat Report]                                       │
  └───────────────────────────────────────────────────────────────┘

  1. User pastes raw threat intel text (e.g., "C2 traffic to 1.2.3.4
     and domain evil.io").
  2. Clicking Submit calls POST /ingest with:
       Authorization: Bearer <google_jwt>
       { "raw_threat_intel": "..." }
  3. The backend pipeline runs synchronously:
       ingest → parse → generate → validate → staging (FROZEN)
  4. A new session card appears with phase = "staging".
  5. Polling begins every 4 seconds via setInterval to watch /state.

## 3  Review Generated Rules (HITL Gate)

When current_phase == "staging" and staging.status == "pending",
the HITL panel is rendered automatically:

  ┌───────────────────────────────────────────────────────────────┐
  │ 🔒 Human-in-the-Loop Review Gate        ● AWAITING           │
  │                                                               │
  │ [Rule 1] YARA · yara-endpoint  ▶ (click to expand content)  │
  │ [Rule 2] Sigma · siem           ▶                            │
  │                                                               │
  │ Reviewer Notes: ________________________________              │
  │                                                               │
  │ [✓ Approve & Deploy]   [✗ Reject & Quarantine]               │
  └───────────────────────────────────────────────────────────────┘

  - Each rule card expands to show raw YARA/Sigma content.
  - The notes field is required for Reject (and recommended for Approve).
  - The reviewer's identity is NOT submitted — it's derived server-side
    from the verified Google JWT, ensuring an unforgeable audit trail.

## 4a  Approve — COMMIT_SUCCESS path

  User clicks [Approve & Deploy]:
    → POST /resume-staging (Bearer token attached)
      { session_id, action: "Approve", notes: "..." }

  Server:
    - Verifies JWT → extracts reviewer_id = email
    - Calls resume_from_staging(state, approve=True, reviewer_id=email)
    - Routes graph: staging → commit_node → END
    - Returns StatusResponse with current_phase = "completed"

  Dashboard:
    - HITL panel disappears
    - Green COMMIT SUCCESS banner appears with commit receipts
    - Polling stops (terminal state)

  ┌───────────────────────────────────────────────────────────────┐
  │ ✅  COMMIT SUCCESS                                            │
  │     commit_id: a3f9b2c1…  · approved by: user@example.com   │
  │     ✓ rule_detect_ip → yara-endpoint   COMMITTED             │
  │     ✓ rule_detect_domain → sigma-siem  COMMITTED             │
  └───────────────────────────────────────────────────────────────┘

## 4b  Reject — CONTAINMENT path

  User clicks [Reject & Quarantine]:
    → POST /resume-staging (Bearer token attached)
      { session_id, action: "Reject", notes: "False positive — CDN IP" }

  Server:
    - Verifies JWT → extracts reviewer_id = email
    - Calls resume_from_staging(state, approve=False, rejection_reason=notes)
    - Routes graph: staging → containment_node → END
    - Returns StatusResponse with current_phase = "error"

  Dashboard:
    - Red CONTAINMENT banner appears with quarantine ID and reason
    - Polling stops (terminal state)

  ┌───────────────────────────────────────────────────────────────┐
  │ ❌  CONTAINMENT — QUARANTINED                                  │
  │     containment_id: 8d12c4f0…                                 │
  │     Reason: False positive — CDN IP                           │
  └───────────────────────────────────────────────────────────────┘

================================================================================
*/

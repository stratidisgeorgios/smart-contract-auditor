'use client'

import { useState, useCallback } from 'react'
import type { AuditReport } from '@/types/report'
import FileUpload from './components/FileUpload'
import ReportView from './components/ReportView'

type AppState = 'idle' | 'scanning' | 'done' | 'error' // four possible states the UI can be in at any time, which decides which screen is rendered (upload form / scanning animation / report / error)

// Read the backend URL from an environment variable.
// In production (Vercel), it points to the Render backend URL.

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

const SCAN_MESSAGES = [ // Rotating status messages are shown during the scanning animation to give feedback to user.
  'Running GenAI and Slither analysis…',
  'Parsing Solidity bytecode…',
  'Detecting reentrancy patterns…',
  'Checking access control vulnerabilities…',
  'Running integer overflow analysis…',
  'Merging and deduplicating findings…',
  'Building vulnerability report…',
]

/* Main page*/

export default function Home() {
  const [file, setFile]               = useState<File | null>(null) // The currently selected File object
  const [fileContent, setFileContent] = useState<string>('') // The raw text content of the selected file
  const [appState, setAppState]       = useState<AppState>('idle') // Controls which screen is shown: upload form | scanning | report | error
  const [report, setReport]           = useState<AuditReport | null>(null) // The audit report returned by the backend
  const [error, setError]             = useState('') // Holds the error message string if the API call fails
  const [msgIdx, setMsgIdx]           = useState(0)

  // Called by FileUpload whenever the user picks or removes a file.
  // We also read the file text here so it's ready when the report renders.

  const handleFileChange = useCallback(async (f: File | null) => {
    setFile(f)
    if (f) {
      try {
        const text = await f.text() // Read the file as a UTF-8 string
        setFileContent(text)
      } catch {
        setFileContent('') // Fall back to empty if reading fails
      }
    } else {
      setFileContent('') // Clear content when the file is removed
    }
  }, [])

  const handleSubmit = async () => {
    if (!file) return
    setAppState('scanning')
    setError('')
    setReport(null)

    let idx = 0
    const ticker = setInterval(() => { // Start cycling through the status messages to provide feedback to user
      idx = (idx + 1) % SCAN_MESSAGES.length
      setMsgIdx(idx)
    }, 1900)

    try {
      const fd = new FormData()
      fd.append('file', file)

      // Calling the backend audit endpoint
      const res = await fetch(`${API_URL}/api/v1/audit`, { method: 'POST', body: fd })
      if (!res.ok) { // Try to extract a human-readable error from the response body. fall back to the HTTP status text if the body isn't JSON
        const body = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(body.detail ?? `Error ${res.status}`)
      }
      const data: AuditReport = await res.json()
      setReport(data)
      setAppState('done') // shows <ReportView>
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error')
      setAppState('error') // shows the error panel

    } finally {
      clearInterval(ticker) // Stop the feedback messages shown to user, whether we succeeded or failed
    }
  }

  const handleReset = () => {
    setFile(null)
    setFileContent('')
    setReport(null)
    setError('')
    setAppState('idle')
  }

  // When the report is ready, we swap to the report view.
  if (appState === 'done' && report) {
    return <ReportView report={report} fileContent={fileContent} onReset={handleReset} />
  }

  //Upload / Scanning / Error screen
  return (
    <main className="relative z-10 min-h-screen flex flex-col items-center justify-center px-4 py-16">
      <div className="w-full max-w-2xl">

        {/* ── Header ── */}
        <header className="text-center mb-10">
          <h1 className="font-display text-5xl sm:text-6xl font-bold tracking-tight mb-4"
              style={{ fontFamily: 'var(--font-oxanium)' }}>
            <span className="grad-text">Smart Contract Auditor</span>
          </h1>
          <p className="text-slate-400 text-sm mb-1">
            Upload your Solidity Smart Contract. Get a detailed security report.
          </p>
          <p className="grad-text text-sm font-medium" style={{ fontFamily: 'var(--font-oxanium)' }}>
            GenAI + Slither-powered analysis
          </p>
        </header>

        {/* Upload / Scanning / Error */}
        {appState === 'idle' && (
          <div className="space-y-4 animate-slide-up">
            <FileUpload file={file} onChange={handleFileChange} />
            <button
              onClick={handleSubmit}
              disabled={!file}
              className={`w-full py-4 rounded-2xl font-display font-bold text-sm uppercase tracking-widest transition-all duration-300
                ${file
                  ? 'grad-btn text-white cursor-pointer shadow-lg shadow-purple-900/30'
                  : 'bg-bg-card text-slate-600 border border-bg-border cursor-not-allowed'
                }`}
              style={{ fontFamily: 'var(--font-oxanium)' }}
            >
              Detect Vulnerabilities
            </button>
          </div>
        )}
        {/* scanning state: animated radar and rotating message */}
        {appState === 'scanning' && <ScanningView message={SCAN_MESSAGES[msgIdx]} />}

        {/* error state: shows the error message and reset button*/}
        {appState === 'error' && (
          <div className="animate-slide-up space-y-4">
            <div className="rounded-2xl border border-red-500/25 bg-red-500/8 p-6">
              <p className="font-mono text-xs text-red-400 mb-2 uppercase tracking-widest">Error</p>
              <p className="text-slate-300 text-sm">{error}</p>
            </div>
            <button
              onClick={handleReset}
              className="w-full py-3 rounded-2xl border border-bg-border text-slate-400 hover:text-brand-cyan hover:border-brand-cyan/30 transition-all text-sm font-mono"
            >
              ← Try again
            </button>
          </div>
        )}
      </div>
    </main>
  )
}

/* Scanning animation */

function ScanningView({ message }: { message: string }) {
  return (
    <div className="animate-fade-in">
      <div className="grad-border overflow-hidden" style={{ height: 280 }}>
        <div className="relative w-full h-full bg-bg-surface rounded-2xl overflow-hidden scan-grid">
          <div className="scan-line" />
          <span className="absolute top-4 left-4 w-5 h-5 border-l-2 border-t-2 border-brand-cyan/60 rounded-tl" />
          <span className="absolute top-4 right-4 w-5 h-5 border-r-2 border-t-2 border-brand-pink/60 rounded-tr" />
          <span className="absolute bottom-4 left-4 w-5 h-5 border-l-2 border-b-2 border-brand-cyan/60 rounded-bl" />
          <span className="absolute bottom-4 right-4 w-5 h-5 border-r-2 border-b-2 border-brand-pink/60 rounded-br" />
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-5">
            <RadarIcon />
            <div className="text-center">
              <p className="font-display font-semibold text-slate-100 text-base mb-1"
                 style={{ fontFamily: 'var(--font-oxanium)' }}>
                Analyzing Smart Contract
              </p>
              <p className="text-slate-500 text-xs transition-all duration-500">{message}</p>
            </div>
          </div>
        </div>
      </div>
      <p className="text-center text-xs text-slate-600 font-sans mt-4">
        This may take 30–60 seconds depending on contract size
      </p>
    </div>
  )
}

/* Radar SVG icon*/
function RadarIcon() {
  return (
    <div className="relative w-16 h-16">
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 64 64" fill="none">
        <circle cx="32" cy="32" r="30" stroke="rgba(0,212,255,0.12)" strokeWidth="1" />
        <circle cx="32" cy="32" r="20" stroke="rgba(155,77,255,0.15)" strokeWidth="1" />
        <circle cx="32" cy="32" r="10" stroke="rgba(255,45,124,0.18)" strokeWidth="1" />
        <line x1="32" y1="2"  x2="32" y2="62" stroke="rgba(0,212,255,0.08)" strokeWidth="0.5" />
        <line x1="2"  y1="32" x2="62" y2="32" stroke="rgba(0,212,255,0.08)" strokeWidth="0.5" />
        <circle cx="32" cy="32" r="2" fill="#9B4DFF" />
      </svg>
      <svg
        className="absolute inset-0 w-full h-full"
        viewBox="0 0 64 64"
        fill="none"
        style={{ animation: 'radarSweep 2.5s linear infinite', transformOrigin: '32px 32px' }}
      >
        <path d="M32 32 L32 2 A30 30 0 0 1 57 47 Z" fill="url(#radarGrad)" opacity="0.35" />
        <line x1="32" y1="32" x2="32" y2="2" stroke="#00D4FF" strokeWidth="1.5" strokeLinecap="round" />
        <defs>
          <radialGradient id="radarGrad" cx="32" cy="32" r="30" gradientUnits="userSpaceOnUse">
            <stop offset="0%"   stopColor="#9B4DFF" />
            <stop offset="100%" stopColor="#00D4FF" stopOpacity="0" />
          </radialGradient>
        </defs>
      </svg>
    </div>
  )
}
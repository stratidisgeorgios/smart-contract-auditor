'use client'

import { useState } from 'react'
import type { AuditReport, Severity, Vulnerability } from '@/types/report'

/* Severity palette */
/*A table that maps each severity level to all the colours needed to
render it across every part of the UI*/
const SEV: Record<Severity, {
  color: string
  bg: string
  border: string
  badgeBg: string
  badgeText: string
  label: string
  cardGrad: string
  cardBorder: string
  cardShadow: string
}> = {
  CRITICAL: {
    color:      '#EF4444',
    bg:         'rgba(239,68,68,0.08)',
    border:     'rgba(239,68,68,0.35)',
    badgeBg:    'rgba(239,68,68,0.22)',
    badgeText:  '#F87171',
    label:      'CRITICAL',
    cardGrad:   'linear-gradient(135deg, rgba(239,68,68,0.28) 0%, rgba(239,68,68,0.10) 45%, #050D1C 80%)',
    cardBorder: 'rgba(239,68,68,0.60)',
    cardShadow: '0 0 20px rgba(239,68,68,0.15), inset 0 1px 0 rgba(239,68,68,0.15)',
  },
  HIGH: {
    color:      '#F97316',
    bg:         'rgba(249,115,22,0.08)',
    border:     'rgba(249,115,22,0.35)',
    badgeBg:    'rgba(249,115,22,0.22)',
    badgeText:  '#FB923C',
    label:      'HIGH',
    cardGrad:   'linear-gradient(135deg, rgba(249,115,22,0.28) 0%, rgba(249,115,22,0.10) 45%, #050D1C 80%)',
    cardBorder: 'rgba(249,115,22,0.60)',
    cardShadow: '0 0 20px rgba(249,115,22,0.15), inset 0 1px 0 rgba(249,115,22,0.15)',
  },
  MEDIUM: {
    color:      '#EAB308',
    bg:         'rgba(234,179,8,0.08)',
    border:     'rgba(234,179,8,0.35)',
    badgeBg:    'rgba(234,179,8,0.22)',
    badgeText:  '#FDE047',
    label:      'MEDIUM',
    cardGrad:   'linear-gradient(135deg, rgba(234,179,8,0.28) 0%, rgba(234,179,8,0.10) 45%, #050D1C 80%)',
    cardBorder: 'rgba(234,179,8,0.60)',
    cardShadow: '0 0 20px rgba(234,179,8,0.15), inset 0 1px 0 rgba(234,179,8,0.15)',
  },
  LOW: {
    color:      '#2563EB',
    bg:         'rgba(37,99,235,0.08)',
    border:     'rgba(37,99,235,0.35)',
    badgeBg:    'rgba(37,99,235,0.22)',
    badgeText:  '#3B82F6',
    label:      'LOW',
    cardGrad:   'linear-gradient(135deg, rgba(37,99,235,0.28) 0%, rgba(37,99,235,0.10) 45%, #050D1C 80%)',
    cardBorder: 'rgba(37,99,235,0.60)',
    cardShadow: '0 0 20px rgba(37,99,235,0.15), inset 0 1px 0 rgba(37,99,235,0.15)',
  },
  INFO: {
    color:      '#6B7280',
    bg:         'rgba(107,114,128,0.08)',
    border:     'rgba(107,114,128,0.25)',
    badgeBg:    'rgba(107,114,128,0.20)',
    badgeText:  '#9CA3AF',
    label:      'INFO',
    cardGrad:   'linear-gradient(135deg, rgba(107,114,128,0.18) 0%, #050D1C 70%)',
    cardBorder: 'rgba(107,114,128,0.35)',
    cardShadow: 'none',
  },
}

const CONF_PCT: Record<string, number> = { HIGH: 95, MEDIUM: 70, LOW: 40 } // Maps the confidence label to a percentage that is shown on the circular progress indicator in the UI
const SIDEBAR_INIT = 7 // How many vulnerabilities to show in the sidebar before showing a "Show more" button

/*Snippet search
Problem: the LLM backend sometimes returns line_numbers=[1] as a fallback
when it can't identify the real line, which would highlight line 1 instead
of the vulnerable code.
Solution: when we have the full file content (passed down from page.tsx),
we scan every line of the file looking for the text from affected_code_snippet.
If we find a match, we use those real line numbers.
Slither already provides correct numbers, so for Slither findings this just confirms them.*/
function findSnippetInFile(fileContent: string, snippet: string): number[] {
  if (!fileContent || !snippet.trim()) return []

  const fileLines    = fileContent.split('\n')
  const snippetLines = snippet
    .trim()
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 2)

  if (snippetLines.length === 0) return []

  // We use the longest line as the search anchor as it's the most least likely to appear in multiple places
  const anchor = snippetLines.reduce((a, b) => (a.length >= b.length ? a : b))
  if (anchor.length < 3) return []

  for (let i = 0; i < fileLines.length; i++) {
    const fileLine = fileLines[i].trim()
    if (
      fileLine === anchor ||
      fileLine.includes(anchor) ||
      (anchor.includes(fileLine) && fileLine.length > 3)
    ) {
      //we found a match, so we build the list of line numbers for the full snippet
      return snippetLines
        .map((_, j) => i + j + 1)
        .filter(n => n <= fileLines.length)
    }
  }

  return [] // Snippet not found in the file
}

/* Root*/
export default function ReportView({
  report,
  fileContent = '',
  onReset,
}: {
  report: AuditReport
  fileContent?: string
  onReset: () => void
}) {
  const { meta, contract_info, statistics, vulnerabilities } = report
  const [sel, setSel]         = useState(0) // Index of the currently selected vulnerability in the sidebar list
  const [showAll, setShowAll] = useState(false)
  const [hoverIdx, setHoverIdx] = useState<number | null>(null) // Which sidebar item the mouse is hovering over

  const visible  = showAll ? vulnerabilities : vulnerabilities.slice(0, SIDEBAR_INIT)
  const hiddenN  = vulnerabilities.length - SIDEBAR_INIT
  const selected = vulnerabilities[sel] ?? null  // the full object for the right panel

  return (
    <div className="min-h-screen flex flex-col gap-4 p-5" style={{ background: '#01030A' }}>

      {/* HEADER CARD */}
      <div style={{
        background: 'linear-gradient(135deg, #00D4FF, #9B4DFF 50%, #FF2D7C)',
        padding: 1,
        borderRadius: 16,
      }}>
        <div
          className="flex items-start justify-between gap-4 px-5 py-4 rounded-2xl"
          style={{ background: '#050D1C' }}
        >
          {/* Left side: title, filename, Solidity version */}
          <div>
            <h1
              className="font-display font-bold text-3xl tracking-tight mb-3"
              style={{
                fontFamily: 'var(--font-oxanium)',
                background: 'linear-gradient(90deg, #00D4FF, #9B4DFF 50%, #FF2D7C)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              Smart Contract Auditor
            </h1>
            <div className="flex items-center gap-2 mb-1.5">
              <FileDocIcon />
              <span className="text-slate-100 font-medium text-sm">{meta.contract_name}</span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-500 font-mono flex-wrap">
              {contract_info?.solidity_version && <span>Solidity: {contract_info.solidity_version}</span>}
              {contract_info?.total_lines > 0   && <span>Lines: {contract_info.total_lines}</span>}
              <span style={{ color: '#4ADE80' }}>✓ Analysis completed</span>
            </div>
          </div>
          
          {/* Right side: shows which analysis engines were active */}
          <div
            className="flex-shrink-0 rounded-xl border px-4 py-3 min-w-[178px]"
            style={{ borderColor: '#1C2D45', background: '#030810' }}
          >
            <p className="text-slate-500 text-xs font-mono uppercase tracking-widest mb-3">
              Analysis Engine
            </p>
            <div className="space-y-2.5">
              {/* GenAI is always active. Slither is green only if it ran successfully */}
              <EngineRow icon={<AiBadgeIcon />}      label="GenAI Semantic" active={true} />
              <EngineRow icon={<SlitherBadgeIcon />} label="Slither Static"  active={meta.slither_available} />
            </div>
          </div>
        </div>
      </div>

      {/* STATS BAR. Five cards in a row: CRITICAL, HIGH, MEDIUM, LOW, and a total card.
          Each card shows the count and has a severity colour assigned. */}
      <div>
        <p className="text-slate-100 text-xl font-semibold mb-3" style={{ fontFamily: 'var(--font-oxanium)' }}>Vulnerabilities</p>
        <div className="grid grid-cols-5 gap-3">
          <StatCard sev="CRITICAL" count={statistics.critical} icon={<EkgIcon    color="#EF4444" />} />
          <StatCard sev="HIGH"     count={statistics.high}     icon={<HighBarIcon   color="#F97316" />} />
          <StatCard sev="MEDIUM"   count={statistics.medium}   icon={<MediumBarIcon color="#EAB308" />} />
          <StatCard sev="LOW"      count={statistics.low}      icon={<LowBarIcon    color="#2563EB" />} />
          <TotalCard count={statistics.total} />
        </div>
      </div>

      {/* TWO-COLUMN LAYOUT
          Left sidebar: scrollable list of vulnerability titles.
          Right panel: detailed view of the currently selected vulnerability. */}
      <div
        className="flex gap-3 flex-1 min-h-0"
        style={{ height: 'calc(100vh - 315px)', minHeight: 500 }}
      >
        {/* LEFT SIDEBAR */}
        <div
          className="flex flex-col rounded-2xl flex-shrink-0 w-64"
          style={{ background: '#050D1C', border: '1px solid #1C2D45' }}
        >
          {/* Header */}
          <div className="px-4 py-3 border-b flex-shrink-0" style={{ borderColor: '#1C2D45' }}>
            <p className="text-slate-400 text-xs uppercase tracking-widest font-mono font-semibold">
              Security Analysis
            </p>
            <p className="text-slate-500 text-xs mt-0.5">
              Vulnerabilities ({vulnerabilities.length})
            </p>
          </div>

          {/* Scrollable list*/}
          <div className="flex-1 overflow-y-auto px-2 py-2" style={{ gap: 4, display: 'flex', flexDirection: 'column' }}>
            {visible.map((v, i) => {
              const s      = SEV[v.severity] ?? SEV.INFO
              const isSel  = sel === i
              const isHov  = hoverIdx === i && !isSel
              return (
                <div key={v.id} style={{ position: 'relative', borderRadius: 12 }}>

                  {/* Gradient border */}
                  <div
                    style={{
                      position:     'absolute',
                      inset:        -1,
                      borderRadius: 13,
                      background:   'linear-gradient(135deg, #00D4FF 0%, #9B4DFF 50%, #FF2D7C 100%)',
                      opacity:       isSel ? 0.90 : isHov ? 0.45 : 0,
                      transition:   'opacity 0.25s ease',
                      pointerEvents: 'none',
                    }}
                  />

                  {/* Button content */}
                  <button
                    onClick={() => setSel(i)}
                    onMouseEnter={() => setHoverIdx(i)}
                    onMouseLeave={() => setHoverIdx(null)}
                    className="w-full text-left"
                    style={{
                      position:   'relative',
                      borderRadius: 12,
                      overflow:   'hidden',
                      background:  isSel
                        ? `linear-gradient(135deg, ${s.color}1A 0%, #081020 100%)`
                        : isHov
                          ? 'linear-gradient(135deg, rgba(0,212,255,0.06) 0%, rgba(155,77,255,0.04) 100%)'
                          : '#050D1C',
                      transition:  'background 0.25s ease',
                    }}
                  >
                    {/* Severity left accent bar */}
                    <div
                      style={{
                        position:   'absolute',
                        left:        0, top: 0, bottom: 0,
                        width:       3,
                        borderRadius: '3px 0 0 3px',
                        background:  s.color,
                        opacity:     isSel ? 1 : isHov ? 0.55 : 0.25,
                        transition:  'opacity 0.25s ease',
                      }}
                    />
                    <div className="px-4 py-3 pl-4">
                      <p
                        style={{
                          fontSize:    14,
                          fontWeight:  500,
                          lineHeight:  1.35,
                          marginBottom: 8,
                          color:        isSel ? '#F1F5F9' : isHov ? '#CBD5E1' : '#94A3B8',
                          transition:  'color 0.2s ease',
                        }}
                      >
                        {v.title}
                      </p>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className="text-xs font-mono font-bold px-1.5 py-0.5 rounded"
                          style={{ background: s.badgeBg, color: s.badgeText }}
                        >
                          {s.label}
                        </span>
                        {v.swc_id && (
                          <span className="text-xs font-mono" style={{ color: '#3D5470' }}>{v.swc_id}</span>
                        )}
                      </div>
                    </div>
                  </button>
                </div>
              )
            })}

            {!showAll && hiddenN > 0 && (
              <button
                onClick={() => setShowAll(true)}
                onMouseEnter={() => setHoverIdx(-1)}
                onMouseLeave={() => setHoverIdx(null)}
                className="w-full py-2.5 text-xs font-mono rounded-xl transition-all duration-200"
                style={{
                  color:      '#60A5FA',
                  background:  hoverIdx === -1 ? 'rgba(96,165,250,0.08)' : 'transparent',
                  border:     `1px solid ${hoverIdx === -1 ? 'rgba(96,165,250,0.3)' : '#1C2D45'}`,
                  transition: 'all 0.2s ease',
                }}
              >
                Show {hiddenN} more ∨
              </button>
            )}
          </div>
        </div>

        {/* RIGHT DETAIL PANEL */}
        <div
          className="flex-1 min-h-0 rounded-2xl"
          style={{
            background: 'linear-gradient(135deg, #00D4FF, #9B4DFF 50%, #FF2D7C)',
            padding: 1,
            boxShadow: '0 0 32px rgba(0,212,255,0.08), 0 0 32px rgba(155,77,255,0.08)',
          }}
        >
          <div
            className="h-full rounded-2xl overflow-y-auto"
            style={{ background: '#050D1C' }}
          >
            {selected ? (
              <VulnDetail vuln={selected} fileContent={fileContent} />
            ) : (
              <div className="flex h-full items-center justify-center text-slate-600 font-mono text-sm">
                Select a vulnerability
              </div>
            )}
          </div>
        </div>
      </div>

      {/* FOOTER */}
      <div className="flex items-center justify-between">
        {/* Goes back to the upload screen */}
        <button
          onClick={onReset}
          className="text-xs font-mono text-slate-500 hover:text-slate-300 transition-colors border rounded-full px-4 py-1.5"
          style={{ borderColor: '#1C2D45' }}
        >
          ← New Audit
        </button>
        {/* Shows which LLM model produced the analysis */}
        <p className="text-xs text-slate-600 font-mono">{meta.llm_model}</p>
      </div>
    </div>
  )
}

/*Vulnerability detail panel*/
function VulnDetail({
  vuln,
  fileContent = '',
}: {
  vuln: Vulnerability
  fileContent?: string
}) {
  const s       = SEV[vuln.severity] ?? SEV.INFO
  const confPct = CONF_PCT[vuln.confidence] ?? 70

  const hasCode = !!( // Only show the code block section if we have something to display
    vuln.affected_code_snippet?.trim() ||
    (fileContent && (vuln.line_numbers?.length ?? 0) > 0)
  )

  return (
    <div className="p-5 space-y-5">

      {/* Severity pill + title + description */}
      <div>
        <span
          className="inline-flex items-center text-xs font-mono font-bold px-3 py-1 rounded-md mb-3"
          style={{ background: s.badgeBg, color: s.badgeText }}
        >
          {s.label}
        </span>
        <h2
          className="font-display font-bold text-2xl text-slate-100 leading-tight mb-2"
          style={{ fontFamily: 'var(--font-oxanium)' }}
        >
          {vuln.title}
        </h2>
        {vuln.description && (
          <p className="text-slate-400 text-sm leading-relaxed">{vuln.description}</p>
        )}
      </div>

      {/* IMPACT (only shown if the LLM provided an exploitation scenario ) */}
      {vuln.exploitation_scenario && (
        <div>
          <p className="text-xs font-mono font-bold uppercase tracking-widest mb-2" style={{ color: '#F97316' }}>
            Impact
          </p>
          <div
            className="rounded-xl p-4 flex gap-3 items-start"
            style={{ background: 'rgba(239,68,68,0.09)', border: '1px solid rgba(239,68,68,0.28)' }}
          >
            <span className="flex-shrink-0 mt-0.5"><TriangleWarnIcon /></span>
            <p className="text-slate-300 text-sm leading-relaxed">{vuln.exploitation_scenario}</p>
          </div>
        </div>
      )}

      {/* LOCATION (code viewer showing the affected lines) */}
      {hasCode && (
        <div>
          <p className="text-xs font-mono font-bold uppercase tracking-widest mb-2" style={{ color: '#2DD4BF' }}>
            Location
          </p>
          <CodeBlock
            snippet={vuln.affected_code_snippet ?? ''}
            lineNumbers={vuln.line_numbers ?? []}
            fileContent={fileContent}
          />
        </div>
      )}

      {/* RECOMMENDATION */}
      {vuln.recommendation && (
        <div>
          <p className="text-xs font-mono font-bold uppercase tracking-widest mb-2" style={{ color: '#4ADE80' }}>
            Recommendation
          </p>
          <div
            className="rounded-xl p-4 flex gap-3 items-start"
            style={{ background: 'rgba(74,222,128,0.07)', border: '1px solid rgba(74,222,128,0.22)' }}
          >
            <span className="flex-shrink-0 mt-0.5"><ShieldCheckIcon /></span>
            <p className="text-slate-300 text-sm leading-relaxed">{vuln.recommendation}</p>
          </div>
        </div>
      )}

      {/* Bottom row: Confidence · Detected By · Category */}
      <div className="grid grid-cols-3 gap-3 pt-1">

        <div
          className="rounded-xl p-4 flex flex-col items-center gap-2"
          style={{ background: '#030810', border: '1px solid #1C2D45' }}
        >
          <p className="text-slate-500 text-xs uppercase tracking-widest font-mono">Confidence</p>
          <ConfCircle pct={confPct} color={s.color} />
          <p className="text-slate-500 text-xs">
            {vuln.confidence === 'HIGH' ? 'Very High' : vuln.confidence === 'MEDIUM' ? 'Medium' : 'Low'}
          </p>
        </div>

        <div
          className="rounded-xl p-4 flex flex-col gap-2"
          style={{ background: '#030810', border: '1px solid #1C2D45' }}
        >
          <p className="text-slate-500 text-xs uppercase tracking-widest font-mono text-center">
            Detected By
          </p>
          <div className="flex flex-col gap-1.5 mt-0.5">
            <DetectedBadge
              icons={<AiSmallIcon />}
              label="AI GenAI"
              active={vuln.source === 'LLM' || vuln.source === 'BOTH'}
              color="#9B4DFF"
            />
            <DetectedBadge
              icons={<SlitherSmallIcon color="#00D4FF" />}
              label="Slither"
              active={vuln.source === 'SLITHER' || vuln.source === 'BOTH'}
              color="#00D4FF"
            />
            <DetectedBadge
              icons={<><AiSmallIcon /><SlitherSmallIcon color="#00D4FF" /></>}
              label="GenAI + Slither"
              active={vuln.source === 'BOTH'}
              color="#FF2D7C"
            />
          </div>
        </div>

        <div
          className="rounded-xl p-4 flex flex-col items-center justify-center gap-1"
          style={{ background: '#030810', border: '1px solid #1C2D45' }}
        >
          <p className="text-slate-500 text-xs uppercase tracking-widest font-mono">Category</p>
          <p
            className="text-slate-100 text-base font-semibold text-center mt-1"
            style={{ fontFamily: 'var(--font-oxanium)' }}
          >
            {vuln.category}
          </p>
          {vuln.swc_id && (
            <p className="text-xs font-mono font-bold" style={{ color: '#9B4DFF' }}>
              {vuln.swc_id}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

/* Code block */
function CodeBlock({
  snippet,
  lineNumbers,
  fileContent = '',
}: {
  snippet: string
  lineNumbers: number[]
  fileContent?: string
}) {
  let lines: string[]
  let firstDisplayLine: number
  let hlSet: Set<number>

  if (fileContent) {
    // Step 1: try to find the snippet in the actual file
    const searched: number[] = snippet.trim()
      ? findSnippetInFile(fileContent, snippet)
      : []

    // Step 2: decide which set of line numbers to use for highlighting
    const effectiveLines: number[] = searched.length > 0 ? searched : lineNumbers

    if (effectiveLines.length > 0) {
      const allLines   = fileContent.split('\n')
      const CONTEXT    = 3
      const minLine    = Math.min(...effectiveLines)
      const maxLine    = Math.max(...effectiveLines)
      const startIdx   = Math.max(0, minLine - 1 - CONTEXT)
      const endIdx     = Math.min(allLines.length - 1, maxLine - 1 + CONTEXT)
      lines            = allLines.slice(startIdx, endIdx + 1)
      firstDisplayLine = startIdx + 1
      hlSet            = new Set(effectiveLines)
    } else {
      // If no usable line info: show the whole file 
      lines            = fileContent.split('\n')
      firstDisplayLine = 1
      hlSet            = new Set<number>()
    }
  } else {
    // No file content: just render the raw snippet the backend sent
    const rawLines = snippet.split('\n')
    let start = 0, end = rawLines.length - 1
    while (start <= end && rawLines[start].trim() === '') start++
    while (end >= start && rawLines[end].trim() === '')   end--
    lines            = rawLines.slice(start, end + 1)
    firstDisplayLine = lineNumbers.length > 0 ? lineNumbers[0] : 1
    hlSet            = new Set(lineNumbers)
  }

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ border: '1px solid #1C2D45', background: '#020508' }}
    >
      <div className="overflow-x-auto overflow-y-auto" style={{ maxHeight: 260 }}>
        <table
          className="border-collapse text-xs font-mono"
          style={{ width: '100%', minWidth: '100%' }}
        >
          <tbody>
            {lines.map((line, i) => {
              const absLine = firstDisplayLine + i
              const hl      = hlSet.has(absLine)
              return (
                <tr key={i} style={hl ? { background: 'rgba(239,68,68,0.14)' } : {}}>

                  {/* Line number — sticky during horizontal scroll */}
                  <td
                    className="select-none text-right sticky left-0"
                    style={{
                      color:         hl ? '#F87171' : '#374D6B',
                      borderRight:   hl ? '2px solid #EF4444' : '1px solid #1C2D45',
                      background:    hl ? 'rgba(239,68,68,0.14)' : '#020508',
                      verticalAlign: 'top',
                      paddingTop: 5, paddingBottom: 5,
                      paddingLeft: 16, paddingRight: 12,
                      minWidth: 48, width: 48,
                    }}
                  >
                    {absLine}
                  </td>

                  {/* Arrow indicator */}
                  <td
                    className="select-none text-center"
                    style={{
                      color:         '#EF4444',
                      paddingTop:    5,
                      verticalAlign: 'top',
                      minWidth: 22, width: 22,
                      fontWeight: 'bold',
                    }}
                  >
                    {hl ? '→' : '\u00a0'}
                  </td>

                  {/* Syntax highlighted code */}
                  <td
                    className="whitespace-pre"
                    style={{
                      verticalAlign: 'top',
                      paddingTop: 5, paddingBottom: 5,
                      paddingLeft: 8, paddingRight: 24,
                    }}
                  >
                    <SolidityLine code={line} highlighted={hl} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* Solidity syntax highlighter -> this is to simulate the colors of solidity code in a Code Editor.
We colourise Solidity code without any external library.
We splits each line into tokens using a regex and assigns a colour to each:
  blue: Solidity keywords (function, uint256, require, etc.)
  green: string 
  yellow: numbers 
  grey: comments
  default: everything else */
function SolidityLine({ code, highlighted }: { code: string; highlighted: boolean }) {
  const baseColor = highlighted ? '#FCA5A5' : '#94A3B8'
  const kwColor   = '#60A5FA'
  const strColor  = '#86EFAC'
  const numColor  = '#FCD34D'
  const cmtColor  = '#4B5563'

  const tokenRe =
    /(\/\/[^\n]*|"[^"]*"|'[^']*'|\b0x[0-9a-fA-F]+\b|\b\d+\b|\b(?:function|require|emit|mapping|address|uint256|uint|bool|string|bytes|public|private|external|internal|view|pure|payable|returns|memory|storage|calldata|if|else|for|while|return|event|modifier|contract|interface|library|constructor|struct|enum|import|pragma|solidity|msg|block|tx|true|false)\b)/g

  const parts: React.ReactElement[] = []
  let last = 0, m: RegExpExecArray | null

  while ((m = tokenRe.exec(code)) !== null) {
    if (m.index > last)
      parts.push(<span key={last} style={{ color: baseColor }}>{code.slice(last, m.index)}</span>)
    const tok = m[0]
    let c = baseColor
    if (tok.startsWith('//'))                            c = cmtColor
    else if (tok.startsWith('"') || tok.startsWith("'")) c = strColor
    else if (/^\d|^0x/.test(tok))                       c = numColor
    else                                                 c = kwColor
    parts.push(<span key={m.index} style={{ color: c }}>{tok}</span>)
    last = m.index + tok.length
  }
  if (last < code.length)
    parts.push(<span key={last} style={{ color: baseColor }}>{code.slice(last)}</span>)
  return <>{parts}</>
}

/* Stat card (The coloured cards at the top (CRITICAL / HIGH / MEDIUM / LOW)) */
function StatCard({ sev, count, icon }: { sev: Severity; count: number; icon: React.ReactNode }) {
  const s = SEV[sev]
  return (
    <div
      className="rounded-xl px-4 py-3 flex items-center justify-between"
      style={{
        background: s.cardGrad,          // always show severity gradient
        border:     `1px solid ${s.cardBorder}`,
        boxShadow:  s.cardShadow,
      }}
    >
      <div>
        <p className="font-display text-3xl font-bold leading-none"
           style={{ fontFamily: 'var(--font-oxanium)', color: s.color }}>
          {count}
        </p>
        <p className="text-xs font-mono uppercase tracking-wider mt-1"
           style={{ color: s.color, opacity: 0.82 }}>
          {s.label}
        </p>
      </div>
      <div style={{ opacity: 0.85 }}>{icon}</div>
    </div>
  )
}

function TotalCard({ count }: { count: number }) {
  return (
    <div
      className="rounded-xl px-4 py-3 flex items-center justify-between"
      style={{
        background: 'linear-gradient(135deg, rgba(107,114,128,0.22) 0%, rgba(107,114,128,0.08) 45%, #050D1C 80%)',
        border:     '1px solid rgba(107,114,128,0.45)',
        boxShadow:  '0 0 20px rgba(107,114,128,0.10), inset 0 1px 0 rgba(107,114,128,0.12)',
      }}
    >
      <div>
        <p className="font-display text-3xl font-bold leading-none text-slate-300"
           style={{ fontFamily: 'var(--font-oxanium)' }}>{count}</p>
        <p className="text-xs font-mono uppercase tracking-wider mt-1" style={{ color: '#9CA3AF', opacity: 0.82 }}>
          Total
        </p>
      </div>
      <span className="text-slate-500 text-2xl font-light leading-none">+</span>
    </div>
  )
}

/*  Confidence circle */
function ConfCircle({ pct, color }: { pct: number; color: string }) {
  const r = 20, circ = 2 * Math.PI * r, dash = (pct / 100) * circ
  return (
    <div className="relative flex items-center justify-center" style={{ width: 56, height: 56 }}>
      <svg className="absolute inset-0 -rotate-90" width="56" height="56" viewBox="0 0 56 56">
        <circle cx="28" cy="28" r={r} fill="none" stroke="#1C2D45" strokeWidth="4" />
        <circle cx="28" cy="28" r={r} fill="none" stroke={color}  strokeWidth="4"
                strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
      </svg>
      <span className="text-slate-200 font-mono text-xs font-bold">{pct}%</span>
    </div>
  )
}

/* Detected By */
function DetectedBadge({
  icons, label, active, color,
}: {
  icons: React.ReactNode; label: string; active: boolean; color: string
}) {
  return (
    <div
      className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs font-mono transition-all"
      style={{
        background: active ? `${color}18` : 'transparent',
        border:     `1px solid ${active ? color + '55' : '#1C2D45'}`,
        color:      active ? color : '#3D4F6B',
        opacity:    active ? 1 : 0.42,
      }}
    >
      <div className="flex items-center gap-0.5 flex-shrink-0">{icons}</div>
      <span className="truncate leading-none">{label}</span>
    </div>
  )
}

/* Engine row*/
function EngineRow({ icon, label, active }: { icon: React.ReactNode; label: string; active: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
        style={{ background: '#050D1C', border: '1px solid #1C2D45' }}
      >
        {icon}
      </div>
      <div>
        <p className="text-slate-300 text-xs leading-none">{label}</p>
        <p className="text-xs font-mono font-bold mt-0.5" style={{ color: active ? '#4ADE80' : '#374151' }}>
          {active ? 'Active' : 'Inactive'}
        </p>
      </div>
    </div>
  )
}

/* ICONS */

function FileDocIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
         stroke="#9B4DFF" strokeWidth="1.5" strokeLinecap="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
    </svg>
  )
}

function AiBadgeIcon() {
  return (
    <div style={{
      width: 20, height: 20, borderRadius: 5, flexShrink: 0,
      background: 'linear-gradient(135deg, #00D4FF 0%, #9B4DFF 100%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: 8, fontWeight: 800, color: '#fff',
      fontFamily: 'monospace', letterSpacing: -0.5,
    }}>AI</div>
  )
}

function SlitherBadgeIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <polygon points="10,1 18,5.5 18,14.5 10,19 2,14.5 2,5.5"
               stroke="#00D4FF" strokeWidth="1.2" fill="rgba(0,212,255,0.10)" />
      <polygon points="10,5 14,7.3 14,12.7 10,15 6,12.7 6,7.3"
               stroke="#00D4FF" strokeWidth="0.8" fill="none" opacity="0.45" />
    </svg>
  )
}

function AiSmallIcon() {
  return (
    <div style={{
      width: 14, height: 14, borderRadius: 3, flexShrink: 0,
      background: 'linear-gradient(135deg, #00D4FF, #9B4DFF)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: 6, fontWeight: 800, color: '#fff',
      fontFamily: 'monospace', letterSpacing: -0.5,
    }}>AI</div>
  )
}

function SlitherSmallIcon({ color = '#00D4FF' }: { color?: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style={{ flexShrink: 0 }}>
      <polygon points="7,0.8 12.5,3.9 12.5,10.1 7,13.2 1.5,10.1 1.5,3.9"
               stroke={color} strokeWidth="1.1" fill={`${color}18`} />
      <polygon points="7,3.5 10,5.2 10,8.8 7,10.5 4,8.8 4,5.2"
               stroke={color} strokeWidth="0.7" fill="none" opacity="0.5" />
    </svg>
  )
}

function TriangleWarnIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
         stroke="#EF4444" strokeWidth="2" strokeLinecap="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9"  x2="12"    y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  )
}

function ShieldCheckIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
         stroke="#4ADE80" strokeWidth="2" strokeLinecap="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  )
}

function EkgIcon({ color }: { color: string }) {
  return (
    <svg width="44" height="24" viewBox="0 0 44 24" fill="none">
      <polyline points="0,12 6,12 9,3 13,21 17,7 21,17 25,12 44,12"
                stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function HighBarIcon({ color }: { color: string }) {
  const heights = [4, 6, 8, 10, 13, 16, 18]
  const maxH    = 18
  return (
    <svg width="34" height={maxH + 2} viewBox={`0 0 34 ${maxH + 2}`} fill="none">
      {heights.map((h, i) => (
        <rect key={i} x={i * 5} y={maxH + 1 - h} width="3.5" height={h} rx="1"
              fill={color} opacity={0.50 + i * 0.072} />
      ))}
    </svg>
  )
}

function MediumBarIcon({ color }: { color: string }) {
  const heights = [9, 11, 13, 13, 13, 11, 9]
  const maxH    = 13
  return (
    <svg width="34" height={maxH + 2} viewBox={`0 0 34 ${maxH + 2}`} fill="none">
      {heights.map((h, i) => (
        <rect key={i} x={i * 5} y={maxH + 1 - h} width="3.5" height={h} rx="1"
              fill={color} opacity={0.70} />
      ))}
    </svg>
  )
}

function LowBarIcon({ color }: { color: string }) {
  const heights = [18, 16, 13, 10, 8, 6, 4]
  const maxH    = 18
  return (
    <svg width="34" height={maxH + 2} viewBox={`0 0 34 ${maxH + 2}`} fill="none">
      {heights.map((h, i) => (
        <rect key={i} x={i * 5} y={maxH + 1 - h} width="3.5" height={h} rx="1"
              fill={color} opacity={0.90 - i * 0.072} />
      ))}
    </svg>
  )
}
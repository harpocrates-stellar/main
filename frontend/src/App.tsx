import { useEffect, useMemo, useState } from 'react'
import {
  AlertCircle,
  BadgeCheck,
  Building2,
  CheckCircle2,
  Clock,
  Copy,
  Fingerprint,
  KeyRound,
  Loader2,
  Shield,
  Upload,
  Wallet,
  XCircle,
} from 'lucide-react'
import type { ChainProofRecord, IdentityTier, RegisterProofResult, TxState } from './stellar'
import { describeTxState } from './stellar'
import { fieldSecret, hasSeeds } from './seedVault'
import type { VerificationEvent } from './verificationFlow'
import EvilEye from './components/EvilEye'
import './App.css'

type Stage = 'idle' | 'hashing' | 'embedding' | 'proving' | 'ready' | 'registered' | 'error'
type View = 'landing' | 'studio' | 'verify'

type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type ProofPackage = {
  fileName: string
  sourceHash: string
  videoHash: string
  metadataHash: string
  proofId: string
  timestamp: string
  tier: IdentityTier
  silentWitness?: SilentWitnessProof
}

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050'
const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

const tiers = [
  {
    id: 'silent',
    title: 'Silent Witness',
    label: 'Anonymous Credential',
    icon: Fingerprint,
    description: 'Noir ZK proof, nullifier replay protection, no public creator identity.',
  },
  {
    id: 'source',
    title: 'Consistent Source',
    label: 'Pseudonymous Wallet',
    icon: KeyRound,
    description: 'Freighter signature links evidence to a recurring Stellar source.',
  },
  {
    id: 'seal',
    title: 'Public Seal',
    label: 'Institutional Issuer',
    icon: Building2,
    description: 'Verified issuer account signs the evidence as an official source. The connected wallet must be registered by the admin first.',
  },
] satisfies Array<{
  id: IdentityTier
  title: string
  label: string
  icon: typeof Fingerprint
  description: string
}>

function hex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

async function sha256(input: ArrayBuffer | string) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return hex(await crypto.subtle.digest('SHA-256', bytes))
}

function shortHash(value: string) {
  if (!value) return 'Not generated'
  return `${value.slice(0, 12)}...${value.slice(-10)}`
}

function TxStatusBadge({ state, hash }: { state: TxState; hash: string }) {
  const [copyStatus, setCopyStatus] = useState('')

  if (state === 'idle') return null

  const config: Record<TxState, { icon: typeof Loader2; label: string; className: string }> = {
    idle: { icon: Loader2, label: 'Idle', className: '' },
    submitting: { icon: Loader2, label: 'Submitting…', className: 'tx-submitting' },
    awaiting_confirmation: { icon: Clock, label: 'Awaiting confirmation…', className: 'tx-pending' },
    confirmed: { icon: CheckCircle2, label: 'Confirmed', className: 'tx-confirmed' },
    failed: { icon: XCircle, label: 'Failed', className: 'tx-failed' },
    timeout: { icon: AlertCircle, label: 'Timed out', className: 'tx-timeout' },
  }

  const { icon: Icon, label, className } = config[state]

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(hash)
      setCopyStatus('Copied!')
      setTimeout(() => setCopyStatus(''), 2000)
    } catch {
      setCopyStatus('Failed')
    }
  }

  return (
    <div className={`tx-status-badge ${className}`} role="status" aria-live="polite">
      <Icon size={14} className={state === 'submitting' ? 'spin' : undefined} aria-hidden="true" />
      <span>{label}</span>
      {hash && (
        <div className="tx-hash-actions">
          <button
            className="tx-hash-copy"
            type="button"
            onClick={() => void handleCopy()}
            title="Copy transaction hash"
            aria-label={`Copy transaction hash: ${hash}`}
          >
            <Copy size={11} aria-hidden="true" />
            {copyStatus || shortHash(hash)}
          </button>
          <a
            className="tx-hash-copy"
            href={`https://stellar.expert/explorer/testnet/tx/${hash}`}
            target="_blank"
            rel="noreferrer"
            title="View on Stellar Expert"
          >
            Explorer ↗
          </a>
        </div>
      )}
    </div>
  )
}

import { useTransactionState } from './hooks/useTransactionState'

function initialView(): View {
  const hash = window.location.hash.replace('#', '')
  return hash === 'studio' || hash === 'verify' ? hash : 'landing'
}

function App() {
  const [currentView, setCurrentView] = useState<View>(initialView)
  const [isScrolled, setIsScrolled] = useState(false)
  const [selectedTier, setSelectedTier] = useState<IdentityTier>('silent')
  const [stage, setStage] = useState<Stage>('idle')
  const [file, setFile] = useState<File | null>(null)
  const [proof, setProof] = useState<ProofPackage | null>(null)
  const [processedVideoUrl, setProcessedVideoUrl] = useState('')
  const [wallet, setWallet] = useState('')
  const [credentialSeed, setCredentialSeed] = useState('')
  const [nullifierSeed, setNullifierSeed] = useState('')
  const [message, setMessage] = useState('Upload evidence to begin.')
  const [verifyHash, setVerifyHash] = useState('')
  const [verifyResult, setVerifyResult] = useState('')
  const { state: txState, send: sendTxEvent } = useTransactionState()
  const [events, setEvents] = useState<VerificationEvent[]>([])
  const [chainProof, setChainProof] = useState<ChainProofRecord | null>(null)
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)

  useEffect(() => {
    if (txState.status === 'awaiting_confirmation' && txState.hash) {
      setMessage('Recovered pending transaction. Polling for finality...')
      const pollStellar = async () => {
        const { pollTransactionStatus } = await import('./transactionVerifier')
        const result = await pollTransactionStatus(txState.hash!, CONTRACT_ID, {
          maxAttempts: 20,
          intervalMs: 3000,
        })
        if (result.status === 'confirmed') {
          sendTxEvent({ type: 'CONFIRMED' })
          setMessage('Registration confirmed on Stellar. Evidence is now on-chain.')
        } else if (result.status === 'failed') {
          sendTxEvent({ type: 'FAILED', error: 'Transaction failed on network' })
          setMessage('Registration failed on network.')
        } else {
          sendTxEvent({ type: 'TIMEOUT' })
          setMessage('Polling timed out. The transaction may still complete.')
        }
      }
      void pollStellar()
    }
  }, [txState.status, txState.hash])

  const selectedTierMeta = useMemo(
    () => tiers.find((tier) => tier.id === selectedTier) ?? tiers[0],
    [selectedTier],
  )

  useEffect(() => {
    const updateScrollState = () => setIsScrolled(window.scrollY > 36)
    updateScrollState()
    window.addEventListener('scroll', updateScrollState, { passive: true })
    return () => window.removeEventListener('scroll', updateScrollState)
  }, [])

  useEffect(() => {
    return () => {
      setCredentialSeed('')
      setNullifierSeed('')
    }
  }, [])

  function openView(view: View) {
    if (view !== 'studio') {
      setCredentialSeed('')
      setNullifierSeed('')
    }
    setCurrentView(view)
    const nextHash = view === 'landing' ? window.location.pathname : `${window.location.pathname}#${view}`
    window.history.replaceState(null, '', nextHash)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  async function connectWallet() {
    try {
      const { connectFreighter, getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE } = await import('./stellar')
      const { checkNetworkMatch } = await import('./networkGuard')
      const publicKey = await connectFreighter()
      setWallet(publicKey)

      const walletPassphrase = await getWalletNetwork()
      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (check.ok) {
        setNetworkMismatch(null)
        setMessage('Wallet connected on Stellar Testnet.')
      } else {
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        setMessage(check.reason)
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Freighter is not available.')
    }
  }

  async function handleEvidence(nextFile: File | null) {
    if (!nextFile) return

    setFile(nextFile)
    setStage('hashing')
    setMessage('Hashing video locally in the browser.')

    try {
      const sourceHash = await sha256(await nextFile.arrayBuffer())
      const proofId = await sha256(`${sourceHash}:${crypto.randomUUID()}`)
      const timestamp = new Date().toISOString()
      setStage('embedding')
      setMessage('Embedding portable Harpocrates metadata into the video.')

      const metadata = {
        protocol: 'harpocrates',
        version: 1,
        tier: selectedTier,
        sourceHash,
        proofId,
        timestamp,
        fileName: nextFile.name,
      }

      const form = new FormData()
      form.append('video', nextFile)
      form.append('metadata', JSON.stringify(metadata))

      const response = await fetch(`${API_BASE}/api/stego/embed`, {
        method: 'POST',
        body: form,
      })

      if (!response.ok) {
        throw new Error('Steganography service did not accept the video.')
      }

      const embeddedBlob = await response.blob()
      const embeddedHash = await sha256(await embeddedBlob.arrayBuffer())
      const headerHash = response.headers.get('X-Harpocrates-Embedded-Hash')
      const metadataHash = response.headers.get('X-Harpocrates-Metadata-Hash')
      if (!headerHash || headerHash !== embeddedHash || !metadataHash) {
        throw new Error('Steganography service returned an invalid evidence package.')
      }

      if (processedVideoUrl) {
        URL.revokeObjectURL(processedVideoUrl)
      }
      const nextVideoUrl = URL.createObjectURL(embeddedBlob)
      setProcessedVideoUrl(nextVideoUrl)
      setProof({
        fileName: `harpocrates-${nextFile.name.replace(/\.[^.]+$/, '')}.mp4`,
        sourceHash,
        videoHash: embeddedHash,
        metadataHash,
        proofId,
        timestamp,
        tier: selectedTier,
      })
      setStage('ready')
      setMessage('Embedded evidence package is ready for Stellar registration.')
    } catch (error) {
      setStage('error')
      setMessage(error instanceof Error ? error.message : 'Evidence processing failed.')
    }
  }

  async function registerProof() {
    if (!proof) return

    if (!CONTRACT_ID) {
      setMessage('Set VITE_HARPOCRATES_REGISTRY_ID after deploying the Soroban contract.')
      return
    }

    if (!wallet) {
      setMessage('Connect Freighter before registering evidence.')
      return
    }

    sendTxEvent({ type: 'SUBMIT' })
    setMessage(`Submitting ${selectedTierMeta.title} proof to Stellar Testnet...`)

    // Re-check network immediately before submission – the user may have
    // switched networks in Freighter after connecting.
    try {
      const { getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE } = await import('./stellar')
      const { checkNetworkMatch } = await import('./networkGuard')
      const walletPassphrase = await getWalletNetwork()
      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (!check.ok) {
        sendTxEvent({ type: 'FAILED', error: 'Network mismatch' })
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        setMessage(check.reason)
        return
      }
      setNetworkMismatch(null)
    } catch {
      sendTxEvent({ type: 'FAILED', error: 'Could not verify wallet network' })
      // If we cannot query the network, abort rather than submit to the wrong chain.
      setMessage('Could not verify wallet network before submitting. Reconnect Freighter and try again.')
      return
    }

    try {
      const proofForRegistration =
        selectedTier === 'silent' && !proof.silentWitness
          ? await attachSilentWitnessProof(proof)
          : proof
      const { registerProofOnStellar } = await import('./stellar')
      const result = await registerProofOnStellar({
        contractId: CONTRACT_ID,
        publicKey: wallet,
        tier: selectedTier,
        videoHash: proofForRegistration.videoHash,
        metadataHash: proofForRegistration.metadataHash,
        proofId: proofForRegistration.proofId,
        silentWitness: proofForRegistration.silentWitness
          ? {
              publicInputs: proofForRegistration.silentWitness.publicInputs,
              proof: proofForRegistration.silentWitness.proof,
            }
          : undefined,
      }, false) // don't wait for confirmation internally
      
      if (result.txState === 'failed') {
          sendTxEvent({ type: 'FAILED', error: result.status })
          setMessage(`Registration failed: ${result.status}`)
          return
      }
      
      if (result.hash) {
          sendTxEvent({ type: 'TX_HASH_RECEIVED', hash: result.hash })
          setMessage(`Transaction submitted. Awaiting confirmation... Hash: ${shortHash(result.hash)}`)
      }
      
      // The useEffect will pick up the awaiting_confirmation state and poll for it.
      await persistRegistration(proofForRegistration, result)
    } catch (error) {
      sendTxEvent({ type: 'FAILED', error: error instanceof Error ? error.message : 'Stellar registration failed.' })
      setMessage(error instanceof Error ? error.message : 'Stellar registration failed.')
    }
  }

  async function verifyEvidence(nextFile: File | null) {
    if (!nextFile) return

    setVerifyResult('Inspecting evidence...')
    setVerifyHash('')
    let hasLocalHash = false

    try {
      const videoHash = await sha256(await nextFile.arrayBuffer())
      setVerifyHash(videoHash)
      hasLocalHash = true

      const { verifyArtifact } = await import('./verificationFlow')
      const result = await verifyArtifact({
        apiBase: API_BASE,
        contractId: CONTRACT_ID,
        file: nextFile,
        videoHash,
        wallet: wallet || undefined,
      })

      setVerifyResult(result.message)
      setEvents(result.events)
      setChainProof(result.chainProof)
    } catch {
      setVerifyResult(
        hasLocalHash
          ? 'Local hash complete. Verification services are unavailable.'
          : 'Verification services are unavailable.',
      )
    }
  }

  async function loadEvents() {
    try {
      const response = await fetch(`${API_BASE}/api/proofs?limit=6`)
      const data = await response.json()
      setEvents(data.events ?? [])
    } catch {
      setMessage('Database event feed is unavailable.')
    }
  }

  async function persistRegistration(nextProof: ProofPackage, result: RegisterProofResult) {
    await fetch(`${API_BASE}/api/proofs/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName: nextProof.fileName,
        videoHash: nextProof.videoHash,
        metadataHash: nextProof.metadataHash,
        proofId: nextProof.proofId,
        tier: nextProof.tier,
        txHash: result.hash,
        txStatus: result.status,
        sourceAddress: wallet,
        contractId: CONTRACT_ID,
        silentWitness:
          nextProof.silentWitness && nextProof.tier === 'silent'
            ? {
                credentialRoot: nextProof.silentWitness.credentialRoot,
                nullifier: nextProof.silentWitness.nullifier,
                proofBytes: nextProof.silentWitness.proofBytes,
                publicInputBytes: nextProof.silentWitness.publicInputBytes,
              }
            : undefined,
      }),
    })
  }

  async function attachSilentWitnessProof(nextProof: ProofPackage) {
    if (!hasSeeds({ credentialSeed, nullifierSeed })) {
      throw new Error('Silent Witness requires your credential and nullifier seeds.')
    }

    const rawCredentialSeed = credentialSeed.trim()
    const rawNullifierSeed = nullifierSeed.trim()
    clearSeeds()

    setStage('proving')
    setMessage('Generating Noir UltraHonk proof in this browser.')
    const [credentialSecret, nullifierSecret] = await Promise.all([
      fieldSecret('credential', rawCredentialSeed),
      fieldSecret('nullifier', rawNullifierSeed),
    ])

    const { generateSilentWitnessProof } = await import('./noirClient')
    const silentWitness = await generateSilentWitnessProof(
      {
        videoHash: nextProof.videoHash,
        credentialSecret,
        nullifierSecret,
      },
      AbortSignal.timeout(180_000), // 3-minute timeout
    )

    const nextWithProof = {
      ...nextProof,
      silentWitness,
    }
    setProof(nextWithProof)
    return nextWithProof
  }

  function clearSeeds() {
    setCredentialSeed('')
    setNullifierSeed('')
  }

  return (
    <main className="app-shell">
      <div className="signal-background" aria-hidden="true">
        <EvilEye
          eyeColor="#c8ceff"
          intensity={0.9}
          pupilSize={0.55}
          irisWidth={0.22}
          glowIntensity={0.28}
          scale={0.72}
          noiseScale={0.85}
          pupilFollow={0.7}
          flameSpeed={0.38}
          backgroundColor="#030305"
        />
        <div className="prismatic-veil" />
      </div>

      <nav className={isScrolled ? 'topbar scrolled' : 'topbar'}>
        <button className="brand" type="button" onClick={() => openView('landing')} title="Home">
          Harpocrates
        </button>
        <div className="navlinks" aria-label="Primary">
          <button className={currentView === 'studio' ? 'active' : ''} type="button" onClick={() => openView('studio')}>
            Evidence
          </button>
          <button className={currentView === 'verify' ? 'active' : ''} type="button" onClick={() => openView('verify')}>
            Verify
          </button>
        </div>
        <div className="network-pill">Stellar Testnet</div>
        <button className="icon-button" type="button" onClick={connectWallet} title="Connect wallet">
          <Wallet size={18} aria-hidden="true" />
          <span>{wallet ? `${wallet.slice(0, 5)}...${wallet.slice(-4)}` : 'Connect'}</span>
        </button>
      </nav>

      {currentView === 'landing' ? (
        <>
      <section className="hero-band">
        <div className="hero-copy">
          <h1>Evidence integrity for silent witnesses.</h1>
          <p className="lede">
            Steganographic video, Noir privacy proofs, Stellar registry — one verifiable chain of custody.
          </p>
          <div className="hero-actions">
            <button className="hero-primary" type="button" onClick={() => openView('studio')}>
              Begin evidence flow
            </button>
            <button className="hero-secondary" type="button" onClick={() => openView('verify')}>
              Verify an artifact
            </button>
          </div>
        </div>
        <div className="signal-panel" aria-label="Protocol status">
          <span>Integrity</span>
          <strong>SHA-256</strong>
          <span>Privacy</span>
          <strong>3 tiers</strong>
          <span>Registry</span>
          <strong>Soroban</strong>
        </div>
      </section>

      <section className="tech-strip">
        <dl className="tech-specs" aria-label="Technical specification">
          <div><dt>Proof system</dt><dd>Noir UltraHonk</dd></div>
          <div><dt>Hash commitment</dt><dd>SHA-256</dd></div>
          <div><dt>On-chain registry</dt><dd>Soroban</dd></div>
          <div><dt>Identity tiers</dt><dd>3 levels</dd></div>
        </dl>
      </section>

      <section className="workflow-band" id="workflow">
        <div className="workflow-heading">
          <h2>How it works</h2>
          <p>From raw video to chain-verifiable evidence in four steps.</p>
        </div>
        <div className="workflow-diagram" aria-label="Harpocrates protocol workflow">
          <svg viewBox="0 0 1120 240" role="img" preserveAspectRatio="xMidYMid meet">
            <defs>
              <marker
                id="flowArrow"
                viewBox="0 0 10 10"
                refX="7"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M0 0 L10 5 L0 10 z" fill="rgba(255,255,255,0.4)" />
              </marker>
            </defs>

            <line className="flow-connector" x1="280" y1="120" x2="320" y2="120" markerEnd="url(#flowArrow)" />
            <line className="flow-connector" x1="560" y1="120" x2="600" y2="120" markerEnd="url(#flowArrow)" />
            <line className="flow-connector" x1="840" y1="120" x2="880" y2="120" markerEnd="url(#flowArrow)" />

            <g className="diagram-node" transform="translate(40 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">01</text>
              <text className="node-title" x="24" y="40">Video</text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">Steganography</text>
              <text className="node-sub" x="24" y="104">SHA-256</text>
            </g>
            <g className="diagram-node" transform="translate(320 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">02</text>
              <text className="node-title" x="24" y="40">Browser</text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">Noir Proof</text>
              <text className="node-sub" x="24" y="104">Nullifier</text>
            </g>
            <g className="diagram-node" transform="translate(600 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">03</text>
              <text className="node-title" x="24" y="40">Soroban</text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">Verifier</text>
              <text className="node-sub" x="24" y="104">Registry</text>
            </g>
            <g className="diagram-node" transform="translate(880 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">04</text>
              <text className="node-title" x="24" y="40">Portal</text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">Extract</text>
              <text className="node-sub" x="24" y="104">Confirm</text>
            </g>
          </svg>
        </div>
      </section>

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <Shield size={16} aria-hidden="true" />
            <span>Harpocrates</span>
          </div>
          <p className="footer-tagline">Privacy-first evidence integrity on Stellar.</p>
          <div className="footer-stack">
            <span>Noir ZK</span>
            <span>SHA-256</span>
            <span>Soroban</span>
          </div>
        </div>
      </footer>
        </>
      ) : null}

      {currentView === 'studio' ? (
      <section className="workspace app-page" id="studio">
        <div className="studio">
          <header className="page-header">
            <h2>Evidence Studio</h2>
            <p aria-live="polite">{message}</p>
            <TxStatusBadge state={txState.status} hash={txState.hash ?? ''} />
          </header>

          {networkMismatch ? (
            <div className="network-mismatch-banner" role="alert">
              <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
              <span>{networkMismatch}</span>
            </div>
          ) : null}

          <label className="dropzone">
            <Upload size={20} aria-hidden="true" />
            <span>{file ? file.name : 'Drop or choose a video file'}</span>
            <input
              type="file"
              accept="video/*"
              onChange={(event) => void handleEvidence(event.target.files?.[0] ?? null)}
            />
          </label>

          <div className="tier-tabs" role="group" aria-label="Identity tier">
{tiers.map((tier) => {
              const Icon = tier.icon
              return (
                <button
                  className={tier.id === selectedTier ? 'tier-tab active' : 'tier-tab'}
                  key={tier.id}
                  type="button"
                  onClick={() => setSelectedTier(tier.id)}
                >
                  <Icon size={14} aria-hidden="true" />
                  {tier.title}
                </button>
              )
            })}
          </div>

          {selectedTier === 'silent' ? (
            <div className="secret-grid">
              <label>
                <span>Credential Seed</span>
                <input
                  type="password"
                  value={credentialSeed}
                  onChange={(event) => setCredentialSeed(event.target.value)}
                  autoComplete="off"
                />
              </label>
              <label>
                <span>Nullifier Seed</span>
                <input
                  type="password"
                  value={nullifierSeed}
                  onChange={(event) => setNullifierSeed(event.target.value)}
                  autoComplete="off"
                />
              </label>
            </div>
          ) : null}

          <dl className="data-list">
            <div><dt>Source Hash</dt><dd>{shortHash(proof?.sourceHash ?? '')}</dd></div>
            <div><dt>Video Hash</dt><dd>{shortHash(proof?.videoHash ?? '')}</dd></div>
            <div><dt>Metadata Hash</dt><dd>{shortHash(proof?.metadataHash ?? '')}</dd></div>
            <div><dt>Proof ID</dt><dd>{shortHash(proof?.proofId ?? '')}</dd></div>
            <div><dt>Tier</dt><dd>{selectedTierMeta.title}</dd></div>
            <div><dt>Nullifier</dt><dd>{shortHash(proof?.silentWitness?.nullifier ?? '')}</dd></div>
            <div><dt>Credential Root</dt><dd>{shortHash(proof?.silentWitness?.credentialRoot ?? '')}</dd></div>
            <div><dt>Stellar Tx</dt><dd>{shortHash(txState.hash ?? '')}</dd></div>
            <div><dt>Tx Status</dt><dd>{txState.status !== 'idle' ? describeTxState(txState.status) : 'Not submitted'}</dd></div>
          </dl>

          {processedVideoUrl ? (
            <a className="download-link" href={processedVideoUrl} download={proof?.fileName ?? 'harpocrates-evidence.mp4'}>
              Download embedded evidence video
            </a>
          ) : null}

          <button
            className="primary-action"
            type="button"
            disabled={!proof || !!networkMismatch || stage === 'hashing' || stage === 'embedding' || stage === 'proving' || txState.status === 'submitting' || txState.status === 'awaiting_confirmation'}
            onClick={() => void registerProof()}
          >
            {stage === 'hashing' || stage === 'embedding' || stage === 'proving' || txState.status === 'submitting' || txState.status === 'awaiting_confirmation' ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <BadgeCheck size={18} aria-hidden="true" />
            )}
            Register proof
          </button>
        </div>

        <aside className="side-rail">
          <div className="rail-block">
            <h3>{selectedTierMeta.title}</h3>
            <p>{selectedTierMeta.description}</p>
          </div>

          <div className="rail-block">
            <h3>Quick Verify</h3>
            <label className="verify-input">
              <input
                type="file"
                accept="video/*"
                onChange={(event) => void verifyEvidence(event.target.files?.[0] ?? null)}
              />
              <span>Choose received video</span>
            </label>
            <div className="verify-result">
              <CheckCircle2 size={14} aria-hidden="true" />
              <p>{verifyResult || 'No verification run yet.'}</p>
            </div>
            <code>{shortHash(verifyHash)}</code>
          </div>

          <div className="rail-block">
            <h3>Chain Registry</h3>
            {chainProof ? (
              <div className="chain-grid">
                <span>Tier</span>
                <strong>{chainProof.tier}</strong>
                <span>Status</span>
                <strong>{chainProof.status}</strong>
                <span>Source</span>
                <code>{chainProof.source ? shortHash(chainProof.source) : 'None'}</code>
                <span>Metadata</span>
                <code>{shortHash(chainProof.metadataHash)}</code>
              </div>
            ) : (
              <p className="muted">No on-chain match loaded.</p>
            )}
          </div>

          <div className="rail-block">
            <h3>Events</h3>
            <button className="verify-input" type="button" onClick={() => void loadEvents()}>
              Refresh NeonDB feed
            </button>
            <div className="event-list">
              {events.length === 0 ? (
                <p>No events loaded.</p>
              ) : (
                events.map((event) => (
                  <div className="event-row" key={event.id}>
                    <strong>{event.event_type}</strong>
                    <span>{event.tx_status ?? event.tier ?? 'untiered'}</span>
                    <code>{shortHash(event.video_hash ?? event.proof_id ?? '')}</code>
                    {event.tx_hash ? <code>{shortHash(event.tx_hash)}</code> : null}
                  </div>
                ))
              )}
            </div>
          </div>
        </aside>
      </section>
      ) : null}

      {currentView === 'verify' ? (
        <section className="workspace app-page verify-page" id="verify">
          <div className="studio verify-studio">
            <header className="page-header">
              <h2>Verify Artifact</h2>
              <p>Inspect a received video against embedded metadata and the Stellar registry.</p>
            </header>
            <label className="dropzone">
              <Upload size={20} aria-hidden="true" />
              <span>Drop or choose a received video</span>
              <input
                type="file"
                accept="video/*"
                onChange={(event) => void verifyEvidence(event.target.files?.[0] ?? null)}
              />
            </label>
            <div className="verify-result large">
              <CheckCircle2 size={14} aria-hidden="true" />
              <p>{verifyResult || 'No verification run yet.'}</p>
            </div>
            <dl className="data-list">
              <div><dt>Received Hash</dt><dd>{shortHash(verifyHash)}</dd></div>
              <div>
                <dt>Chain Status</dt>
                <dd>{chainProof ? (chainProof.status === 2 ? 'Revoked' : 'Confirmed') : 'Not loaded'}</dd>
              </div>
            </dl>
          </div>

          <aside className="side-rail">
            <div className="rail-block">
              <h3>Chain Registry</h3>
              {chainProof ? (
                <div className="chain-grid">
                  <span>Tier</span>
                  <strong>{chainProof.tier}</strong>
                  <span>Status</span>
                  <strong>{chainProof.status}</strong>
                  <span>Source</span>
                  <code>{chainProof.source ? shortHash(chainProof.source) : 'None'}</code>
                  <span>Metadata</span>
                  <code>{shortHash(chainProof.metadataHash)}</code>
                </div>
              ) : (
                <p className="muted">No on-chain match loaded.</p>
              )}
            </div>

            <div className="rail-block">
              <h3>Events</h3>
              <button className="verify-input" type="button" onClick={() => void loadEvents()}>
                Refresh NeonDB feed
              </button>
              <div className="event-list">
                {events.length === 0 ? (
                  <p>No events loaded.</p>
                ) : (
                  events.map((event) => (
                    <div className="event-row" key={event.id}>
                      <strong>{event.event_type}</strong>
                      <span>{event.tx_status ?? event.tier ?? 'untiered'}</span>
                      <code>{shortHash(event.video_hash ?? event.proof_id ?? '')}</code>
                      {event.tx_hash ? <code>{shortHash(event.tx_hash)}</code> : null}
                    </div>
                  ))
                )}
              </div>
            </div>
          </aside>
        </section>
      ) : null}
    </main>
  )
}

export default App

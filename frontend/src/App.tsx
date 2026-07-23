import { useEffect, useState } from 'react'
import { Wallet } from 'lucide-react'
import EvilEye from './components/EvilEye'
import { LandingView } from './views/LandingView'
import { StudioView } from './views/StudioView'
import { VerifyView } from './views/VerifyView'
import { useWallet } from './hooks/useWallet'
import { useEvidence } from './hooks/useEvidence'
import { useVerification } from './hooks/useVerification'
import type { View } from './types'
import './App.css'

function initialView(): View {
  const hash = window.location.hash.replace('#', '')
  return hash === 'studio' || hash === 'verify' ? hash : 'landing'
}

function App() {
  const [currentView, setCurrentView] = useState<View>(initialView)
  const [isScrolled, setIsScrolled] = useState(false)

  const { wallet, networkMismatch, connectWallet } = useWallet()
  const evidence = useEvidence()
  const verification = useVerification()

  useEffect(() => {
    const updateScrollState = () => setIsScrolled(window.scrollY > 36)
    updateScrollState()
    window.addEventListener('scroll', updateScrollState, { passive: true })
    return () => window.removeEventListener('scroll', updateScrollState)
  }, [])

  function openView(view: View) {
    setCurrentView(view)
    const nextHash =
      view === 'landing'
        ? window.location.pathname
        : `${window.location.pathname}#${view}`
    window.history.replaceState(null, '', nextHash)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  async function handleConnectWallet() {
    try {
      await connectWallet()
    } catch {
      // mismatch message already stored in networkMismatch state by the hook
    }
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
          <button
            className={currentView === 'studio' ? 'active' : ''}
            type="button"
            onClick={() => openView('studio')}
          >
            Evidence
          </button>
          <button
            className={currentView === 'verify' ? 'active' : ''}
            type="button"
            onClick={() => openView('verify')}
          >
            Verify
          </button>
        </div>
        <div className="network-pill">Stellar Testnet</div>
        <button
          className="icon-button"
          type="button"
          onClick={() => void handleConnectWallet()}
          title="Connect wallet"
        >
          <Wallet size={18} aria-hidden="true" />
          <span>{wallet ? `${wallet.slice(0, 5)}...${wallet.slice(-4)}` : 'Connect'}</span>
        </button>
      </nav>

      {currentView === 'landing' ? (
        <LandingView onOpenStudio={() => openView('studio')} onOpenVerify={() => openView('verify')} />
      ) : null}

      {currentView === 'studio' ? (
        <StudioView
          wallet={wallet}
          evidence={{ ...evidence, networkMismatch: networkMismatch ?? evidence.networkMismatch }}
          verification={verification}
        />
      ) : null}

      {currentView === 'verify' ? (
        <VerifyView wallet={wallet} verification={verification} />
      ) : null}
    </main>
  )
}

export default App

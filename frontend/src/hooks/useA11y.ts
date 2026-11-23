import { useCallback, useEffect, useRef, useState } from 'react'

/** Strip values that could leak private evidence data from live-region text. */
function sanitizeAnnouncement(raw: string): string {
  return raw
    // Remove Stellar public keys and contract IDs (G.../C... 56 chars) BEFORE hex
    // so that uppercase base32 addresses are not partially matched as hex first.
    .replace(/\b[GC][A-Z2-7]{55}\b/g, '[address]')
    // Remove hex strings longer than 8 characters (hashes, proofs, nullifiers)
    .replace(/\b[0-9a-f]{9,}\b/gi, '[redacted]')
    // Remove unix-style file paths
    .replace(/(\/[\w.-]+){2,}/g, '[path]')
    // Remove Windows-style file paths
    .replace(/[A-Za-z]:\\[\S]+/g, '[path]')
    .trim()
}

/**
 * Manages a sanitised live-region message.
 * The politeness level (polite vs assertive) is controlled by the `aria-live`
 * attribute on the rendered element. Call `announce(msg)` to update the message;
 * the text is sanitised before storage so no evidence hashes or addresses leak.
 */
export function useLiveRegion() {
  const [message, setMessage] = useState('')

  const announce = useCallback((raw: string) => {
    setMessage(sanitizeAnnouncement(raw))
  }, [])

  return { message, announce }
}

export type Stage = 'idle' | 'hashing' | 'embedding' | 'proving' | 'ready' | 'registered' | 'error' | 'cancelled'

const STAGE_LABELS: Record<Stage, string> = {
  idle: 'Ready',
  hashing: 'Hashing video\u2026',
  embedding: 'Embedding metadata\u2026',
  proving: 'Generating proof\u2026',
  ready: 'Evidence package ready',
  registering: 'Registering evidence\u2026',
  registered: 'Registration submitted',
  error: 'An error occurred',
  cancelled: 'Cancelled',
}

export function useA11yStage(stage: Stage) {
  const isBusy = stage === 'hashing' || stage === 'embedding' || stage === 'proving' || stage === 'registering'
  const statusLabel = STAGE_LABELS[stage]
  return { statusLabel, isBusy }
}

export function useFocusReturn(triggerRef: React.RefObject<HTMLElement | null>, shouldReturn: boolean) {
  const prevShouldReturn = useRef(shouldReturn)
  useEffect(() => {
    if (prevShouldReturn.current && !shouldReturn) {
      triggerRef.current?.focus()
    }
    prevShouldReturn.current = shouldReturn
  }, [shouldReturn, triggerRef])
}

/**
 * Restores keyboard focus after an evidence stage changes.
 *
 * Focus moves only when the control the user was on did not survive the
 * transition (it was removed or disabled), so progress updates never steal
 * focus from a control that is still usable. The `ready` stage targets the next
 * action control; every other stage targets the concise status heading, so
 * assistive technology announces the stage instead of re-reading the page.
 */
export function useStageFocus(
  stage: Stage,
  statusTargetRef: React.RefObject<HTMLElement | null>,
  nextActionRef?: React.RefObject<HTMLElement | null>,
) {
  const previousStageRef = useRef(stage)
  const lastFocusedRef = useRef<HTMLElement | null>(null)

  useEffect(() => {
    const trackFocus = (event: FocusEvent) => {
      if (event.target instanceof HTMLElement) lastFocusedRef.current = event.target
    }
    document.addEventListener('focusin', trackFocus)
    return () => document.removeEventListener('focusin', trackFocus)
  }, [])

  useEffect(() => {
    if (previousStageRef.current === stage) return
    previousStageRef.current = stage

    const previouslyFocused = lastFocusedRef.current
    if (!previouslyFocused) return

    const controlLost =
      !previouslyFocused.isConnected ||
      (previouslyFocused as HTMLButtonElement).disabled === true
    if (!controlLost) return

    const nextAction = nextActionRef?.current
    const usableNextAction =
      nextAction instanceof HTMLButtonElement && !nextAction.disabled ? nextAction : null
    const target = stage === 'ready' && usableNextAction ? usableNextAction : statusTargetRef.current
    if (!target) return

    target.focus()
    lastFocusedRef.current = target
  }, [stage, statusTargetRef, nextActionRef])
}

export function useSkipLink() {
  const mainRef = useRef<HTMLElement | null>(null)
  const handleSkip = useCallback((e: React.MouseEvent | React.KeyboardEvent) => {
    e.preventDefault()
    if (mainRef.current) {
      mainRef.current.tabIndex = -1
      mainRef.current.focus()
    }
  }, [])
  return { mainRef, handleSkip }
}

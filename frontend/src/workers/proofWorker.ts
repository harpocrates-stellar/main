/// <reference lib="webworker" />
import { generateSilentWitnessProof } from '../noirClient'
import { CircuitInputError } from '../circuitInputSchema'
import {
  PROOF_WORKER_PROTOCOL_VERSION,
  RELOAD_REQUIRED_MESSAGE,
  checkWorkerProtocolCompatibility,
} from '../proofWorkerMemory'
import type { WorkerRequest, WorkerResponse, TransferableProofInput } from './proofWorker.types'
import { resolveThreadCount } from './threadCount'

let activeRequestId: string | null = null
let cancelRequestedFor: string | null = null

function post(msg: WorkerResponse) {
  ;(self as unknown as Worker).postMessage(msg)
}

function bufToStr(buf: ArrayBuffer): string {
  return new TextDecoder().decode(buf)
}

function zeroInput(input: TransferableProofInput) {
  new Uint8Array(input.credentialSecret).fill(0)
  new Uint8Array(input.nullifierSecret).fill(0)
}

async function handleGenerate(requestId: string, input: TransferableProofInput) {
  if (activeRequestId !== null) {
    post({ type: 'ERROR', requestId, code: 'BUSY', message: 'A proof is already being generated.' })
    return
  }
  activeRequestId = requestId
  cancelRequestedFor = null

  try {
    const credentialSecret = bufToStr(input.credentialSecret)
    const nullifierSecret = bufToStr(input.nullifierSecret)
    // Zero transferable buffers as soon as strings are materialised so a later
    // terminate()/cancel cannot leave secret bytes resident in the ArrayBuffers.
    zeroInput(input)

    if (cancelRequestedFor === requestId) {
      post({ type: 'CANCELLED', requestId })
      return
    }

    post({ type: 'PROGRESS', requestId, stage: 'loading_circuits' })
    post({ type: 'PROGRESS', requestId, stage: 'executing_helper' })
    post({ type: 'PROGRESS', requestId, stage: 'executing_main' })
    post({ type: 'PROGRESS', requestId, stage: 'generating_proof' })

    const proof = await generateSilentWitnessProof({
      videoHash: input.videoHash,
      credentialSecret,
      nullifierSecret,
      inputSchemaVersion: input.inputSchemaVersion,
      verifierScope: input.verifierScope,
      epoch: input.epoch,
    }, { threadCount: resolveThreadCount() })
    post({ type: 'RESULT', requestId, proof })
  } catch (err) {
    if (cancelRequestedFor === requestId) {
      post({ type: 'CANCELLED', requestId })
      return
    }
    const code = err instanceof CircuitInputError
      ? ({
          invalid_input: 'INVALID_INPUT',
          unsupported_input_schema: 'UNSUPPORTED_INPUT_SCHEMA',
          artifact_mismatch: 'ARTIFACT_MISMATCH',
          invalid_proof_output: 'INVALID_PROOF_OUTPUT',
          circuit_load_failed: 'CIRCUIT_LOAD_FAILED',
          proof_worker_memory_exceeded: 'MEMORY_LIMIT_EXCEEDED',
          proof_generation_failed: 'PROOF_GENERATION_FAILED',
        } as const)[err.code]
      : 'PROOF_GENERATION_FAILED'
    post({
      type: 'ERROR',
      requestId,
      code,
      message: err instanceof CircuitInputError ? err.code : 'proof_generation_failed',
    })
  } finally {
    zeroInput(input)
    if (activeRequestId === requestId) {
      activeRequestId = null
    }
    if (cancelRequestedFor === requestId) {
      cancelRequestedFor = null
    }
  }
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data
  if (!msg || typeof msg !== 'object') {
    post({
      type: 'ERROR',
      protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
      requestId: '',
      code: 'PROTOCOL_VERSION_MISMATCH',
      message: RELOAD_REQUIRED_MESSAGE,
      reloadRequired: true,
    })
    return
  }
  const compatibility = checkWorkerProtocolCompatibility(
    msg.protocolVersion ?? PROOF_WORKER_PROTOCOL_VERSION,
    PROOF_WORKER_PROTOCOL_VERSION,
  )
  if (!compatibility.compatible) {
    // Reject before reading or materialising transferred secret buffers; zero
    // any attached buffers defensively so witness bytes cannot linger.
    if (msg.type === 'GENERATE_PROOF' && msg.input) {
      if (msg.input.credentialSecret instanceof ArrayBuffer) {
        new Uint8Array(msg.input.credentialSecret).fill(0)
      }
      if (msg.input.nullifierSecret instanceof ArrayBuffer) {
        new Uint8Array(msg.input.nullifierSecret).fill(0)
      }
    }
    post({
      type: 'ERROR',
      protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
      requestId: typeof msg.requestId === 'string' ? msg.requestId : '',
      code: 'PROTOCOL_VERSION_MISMATCH',
      message: RELOAD_REQUIRED_MESSAGE,
      reloadRequired: true,
    })
    return
  }
  if (msg.type === 'GENERATE_PROOF') {
    void handleGenerate(msg.requestId, msg.input)
  }
  // CANCEL is handled by the main thread terminating this worker outright —
  // no in-worker cancel logic needed since generateProof can't be interrupted mid-flight.
}

post({ type: 'READY', protocolVersion: PROOF_WORKER_PROTOCOL_VERSION })
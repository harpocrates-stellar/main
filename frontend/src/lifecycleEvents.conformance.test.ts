/**
 * Browser-side conformance runner for `contracts/vectors/lifecycle_events_v1.json` (`hpx-ev/1`).
 */

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  LIFECYCLE_EVENT_CODEC_ID,
  LIFECYCLE_EVENT_SPECS,
  LifecycleEventError,
  decodeExactScVal,
  decodeLifecycleEvent,
} from './lifecycleEvents'
import type {
  LifecycleEventRejectCode,
  StructuredEventAtom,
  StructuredPayloadEntry,
} from './lifecycleEvents'

type CorpusCase = {
  id: string
  event_name: string
  entrypoint: string
  description: string
  topics: StructuredEventAtom[]
  payload: StructuredPayloadEntry[]
  topics_canonical: string
  payload_canonical: string
  topics_xdr_hex: string
  data_xdr_hex: string
  accept: boolean
  reject_code: LifecycleEventRejectCode | null
}

type CorpusFile = {
  format: string
  version: number
  codec: string
  event_schemas: Record<string, unknown>
  cases: CorpusCase[]
}

const here = dirname(fileURLToPath(import.meta.url))
const corpusPath = resolve(here, '../../contracts/vectors/lifecycle_events_v1.json')
const corpus = JSON.parse(readFileSync(corpusPath, 'utf-8')) as CorpusFile

describe('lifecycle event interoperability corpus (hpx-ev/1)', () => {
  it('validates corpus header and schema inventory', () => {
    expect(corpus.format).toBe('harpocrates.lifecycle-events')
    expect(corpus.version).toBe(1)
    expect(corpus.codec).toBe(LIFECYCLE_EVENT_CODEC_ID)
    expect(Object.keys(corpus.event_schemas).sort()).toEqual(
      Object.keys(LIFECYCLE_EVENT_SPECS).sort(),
    )
    expect(corpus.cases.filter((c) => c.accept)).toHaveLength(28)
    expect(corpus.cases.filter((c) => !c.accept)).toHaveLength(8)
  })

  for (const testCase of corpus.cases) {
    if (testCase.accept) {
      it(`decodes positive transition ${testCase.id}`, () => {
        const decoded = decodeLifecycleEvent(
          testCase.topics_xdr_hex,
          testCase.data_xdr_hex,
        )
        expect(decoded.event_name).toBe(testCase.event_name)
        expect(decoded.topics).toEqual(testCase.topics)
        expect(decoded.payload).toEqual(testCase.payload)
        expect(decoded.topics_canonical).toBe(testCase.topics_canonical)
        expect(decoded.payload_canonical).toBe(testCase.payload_canonical)
      })
    } else {
      it(`rejects negative boundary ${testCase.id} with ${testCase.reject_code}`, () => {
        let caught: unknown = null
        try {
          decodeLifecycleEvent(testCase.topics_xdr_hex, testCase.data_xdr_hex)
        } catch (err) {
          caught = err
        }
        expect(caught).toBeInstanceOf(LifecycleEventError)
        expect((caught as LifecycleEventError).code).toBe(testCase.reject_code)
      })
    }
  }

  it('covers scalar and defensive wire error branches', () => {
    expect(decodeExactScVal('0000000000000001').canonical).toBe('bool:true')
    expect(decodeExactScVal('0000000000000000').canonical).toBe('bool:false')
    expect(decodeExactScVal('00000001').canonical).toBe('void:null')
    expect(decodeExactScVal('0000001200000001' + 'cd'.repeat(32)).canonical).toBe(
      'address_contract:' + 'cd'.repeat(32),
    )

    for (const bad of [
      'abc',
      'zzzz',
      '0000000000000002',
      '0000000500000001',
      '0000001200000001aabb',
      '0000000f00000000',
      '0000000f000000012d000000',
      '0000001000000000',
      '0000001100000000',
      '000000120000000000000009' + '11'.repeat(32),
      '0000001200000009',
      '000000ff',
    ]) {
      expect(() => decodeExactScVal(bad)).toThrow(LifecycleEventError)
    }

    const emptyMap = '000000110000000100000000'
    expect(() => decodeLifecycleEvent('00000001', emptyMap)).toThrow(LifecycleEventError)
    expect(() =>
      decodeLifecycleEvent('0000001000000001000000010000000f0000000474657374', emptyMap),
    ).toThrow(LifecycleEventError)
  })
})

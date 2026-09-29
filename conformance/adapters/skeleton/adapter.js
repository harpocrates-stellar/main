#!/usr/bin/env node
// Minimal adapter skeleton (Node, no dependencies): copy, then implement more ops.
// Protocol hpx-conformance-adapter/1: one JSON request per line in, one JSON response per line out.
//   request : {"id": "...", "op": "hex32_normalize", "input": {...}}
//   success : {"id": "...", "ok": true,  "output": {...}}
//   failure : {"id": "...", "ok": false, "code": "<stable reason code>", "detail": {...}?}
// Rules: never echo input (only field NAMES in `detail`), never print to stdout except responses,
// answer `unsupported_op` for anything you do not implement.
const readline = require('node:readline')

const ops = {
  hex32_normalize({ value }) {
    if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) return fail('invalid_hex32')
    return { hex: value.toLowerCase() }
  },
}
const fail = (code, detail) => ({ __fail: true, code, detail })

readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let req
  try { req = JSON.parse(line) } catch { return send({ id: null, ok: false, code: 'bad_request' }) }
  if (req.op === 'hello') {
    return send({ id: req.id, ok: true, output: { protocol: 'hpx-conformance-adapter/1', ops: Object.keys(ops),
      implementation: { name: 'skeleton', version: '0.0.0', language: 'javascript' } } })
  }
  const fn = ops[req.op]
  if (!fn) return send({ id: req.id, ok: false, code: 'unsupported_op' })
  try {
    const out = fn(req.input)
    send(out && out.__fail ? { id: req.id, ok: false, code: out.code, ...(out.detail ? { detail: out.detail } : {}) }
                           : { id: req.id, ok: true, output: out })
  } catch { send({ id: req.id, ok: false, code: 'internal_error' }) }
})
function send(o) { process.stdout.write(JSON.stringify(o) + '\n') }

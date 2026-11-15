export class CliFormatError extends Error {
  readonly exitCode = 2

  constructor(message: string) {
    super(message)
    this.name = 'CliFormatError'
  }
}

export function resolveHashOutput(
  algorithm: string,
  bytes: number,
  digest: string,
  format: string,
): string {
  if (format === 'text') {
    return digest
  }
  if (format === 'json') {
    return JSON.stringify(
      {
        algorithm,
        digest,
        bytes,
      },
      null,
      2,
    )
  }
  throw new CliFormatError('invalid --output value: expected "text" or "json"')
}

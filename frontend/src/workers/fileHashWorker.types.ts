import type { HashProgress } from '../utils'

export type FileHashWorkerRequest = {
  type: 'HASH'
  file: File
}

export type FileHashWorkerResponse =
  | { type: 'PROGRESS'; progress: HashProgress }
  | { type: 'RESULT'; hash: string }
  | { type: 'ERROR'; message: string }

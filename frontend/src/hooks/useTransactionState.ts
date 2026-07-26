import { useEffect, useRef, useState } from 'react'
import { TransactionStateMachine, type TransactionMachineState, type TxEvent } from '../transactionStateMachine'

export function useTransactionState() {
  const machineRef = useRef<TransactionStateMachine | null>(null)
  if (!machineRef.current) {
    machineRef.current = new TransactionStateMachine()
  }

  const [state, setState] = useState<TransactionMachineState>(machineRef.current.getState())

  useEffect(() => {
    const unsubscribe = machineRef.current!.subscribe((nextState) => {
      setState(nextState)
    })
    return unsubscribe
  }, [])

  const send = (event: TxEvent) => {
    machineRef.current!.send(event)
  }

  return { state, send }
}

import { assert } from 'superstruct'
import { encode as hexEncode, decode as hexDecode } from '@stablelib/hex'
import { equal } from '@stablelib/constant-time'
import { decode } from '@stablelib/base64'
import unfetch from 'isomorphic-unfetch'

import { CommitTransaction, VerificationTransaction, VerificationTransactionStruct } from './types'

export async function verifyStellar(transaction: CommitTransaction, testing: boolean | undefined): Promise<VerificationTransaction> {
  const baseUrl = testing ? 'https://horizon-testnet.stellar.org' : 'https://horizon.stellar.org'

  const txUrl = `${baseUrl}/transactions/${transaction.transactionId}`
  const txResp = await unfetch(txUrl)

  if (!txResp.ok) {
    throw new Error(`Stellar : failed to fetch transaction Id '${transaction.transactionId}' :  status ${txResp.status} : ${txResp.statusText}`)
  }

  const tx = (await txResp.json()) as {
    memo: string
    memo_type: string
    ledger: number
    successful: boolean
  }

  if (!tx) {
    throw new Error(`Stellar : failed to convert response JSON for transaction Id '${transaction.transactionId}'`)
  }

  if (!tx.successful) {
    throw new Error(`Stellar : failed to find 'successful' field, or it was false, in response JSON for transaction Id '${transaction.transactionId}'`)
  }

  if (!tx.memo_type || tx.memo_type !== 'hash') {
    throw new Error(`Stellar : failed to find 'memo_type' field, or it was not 'hash', in response JSON for transaction Id '${transaction.transactionId}'`)
  }

  if (!tx.memo || tx.memo === '') {
    throw new Error(`Stellar : failed to find 'memo' field in response JSON for transaction Id '${transaction.transactionId}'`)
  }

  // memo is returned as a base64 encoded string (not url safe string)
  const txMemo = decode(tx.memo)

  if (!equal(txMemo, hexDecode(transaction.inputHash))) {
    throw new Error(
      `Stellar : failed comparing 'memo' to the on-chain 'memo'. Expected '${transaction.inputHash}' but received '${hexEncode(
        txMemo,
      ).toLowerCase()}' from transaction Id '${transaction.transactionId}'`,
    )
  }

  if (!tx.ledger || tx.ledger !== parseInt(transaction.blockId, 10)) {
    throw new Error(`Stellar : failed to find 'ledger' field, or it did not match transaction 'blockId' for transaction Id '${transaction.transactionId}'`)
  }

  const ledgerResp = await unfetch(`${baseUrl}/ledgers/${transaction.blockId}`)

  if (!ledgerResp.ok) {
    throw new Error(`Stellar : failed to fetch ledger '${transaction.blockId}'`)
  }

  const ledger = (await ledgerResp.json()) as {
    closed_at: string
    sequence: number
  }

  if (!tx.ledger || tx.ledger !== parseInt(transaction.blockId, 10)) {
    throw new Error(`Stellar : failed to find 'ledger' field, or it did not match transaction 'blockId' for transaction Id '${transaction.transactionId}'`)
  }

  // A browser page with Transaction Details

  const urlHumanBase = 'https://stellar.expert/explorer'
  const urlHumanEnv = testing ? 'testnet' : 'public'
  const urlHuman = `${urlHumanBase}/${urlHumanEnv}/tx/${transaction.transactionId}`

  const verification: VerificationTransaction = {
    ok: true,
    offline: false,
    intent: 'xlm',
    inputHash: transaction.inputHash,
    transactionId: transaction.transactionId,
    blockId: transaction.blockId,
    timestamp: new Date(ledger.closed_at),
    urlApi: txUrl,
    urlWeb: urlHuman,
  }

  assert(verification, VerificationTransactionStruct)
  return verification
}

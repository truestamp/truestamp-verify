import { assert } from 'superstruct'
import { encode as hexEncode, decode as hexDecode } from '@stablelib/hex'
import { equal } from '@stablelib/constant-time'
import { decodeURLSafe } from '@stablelib/base64'
import fetch from 'isomorphic-unfetch'

import { CommitTransaction, Verification, VerificationStruct } from './types'

export async function verifyStellar(
  transaction: CommitTransaction,
  testing: boolean | undefined,
): Promise<Verification> {
  const baseUrl = testing
    ? 'https://horizon-testnet.stellar.org'
    : 'https://horizon.stellar.org'

  const txUrl = `${baseUrl}/transactions/${transaction.transactionId}`
  const txResp = await fetch(txUrl)

  if (!txResp.ok) {
    throw new Error(
      `Stellar : failed to fetch transaction Id '${transaction.transactionId}'`,
    )
  }

  const tx = (await txResp.json()) as {
    memo: string
    memo_type: string
    ledger: number
    successful: boolean
  }

  if (!tx) {
    throw new Error(
      `Stellar : failed to convert response JSON for transaction Id '${transaction.transactionId}'`,
    )
  }

  if (!tx.successful) {
    throw new Error(
      `Stellar : failed to find 'successful' field, or it was false, in response JSON for transaction Id '${transaction.transactionId}'`,
    )
  }

  if (!tx.memo_type || tx.memo_type !== 'hash') {
    throw new Error(
      `Stellar : failed to find 'memo_type' field, or it was not 'hash', in response JSON for transaction Id '${transaction.transactionId}'`,
    )
  }

  if (!tx.memo || tx.memo === '') {
    throw new Error(
      `Stellar : failed to find 'memo' field in response JSON for transaction Id '${transaction.transactionId}'`,
    )
  }

  // memo is returned as a base64 encoded string
  const txMemo = decodeURLSafe(tx.memo)

  if (!equal(txMemo, hexDecode(transaction.inputHash))) {
    throw new Error(
      // eslint-disable-next-line prettier/prettier
      `Stellar : failed comparing 'memo' to the on-chain 'memo'. Expected '${transaction.inputHash}' but received '${hexEncode(txMemo).toLowerCase()}' from transaction Id '${transaction.transactionId}'`,
    )
  }

  if (!tx.ledger || tx.ledger !== parseInt(transaction.blockId, 10)) {
    throw new Error(
      `Stellar : failed to find 'ledger' field, or it did not match transaction 'blockId' for transaction Id '${transaction.transactionId}'`,
    )
  }

  const ledgerResp = await fetch(`${baseUrl}/ledgers/${transaction.blockId}`)

  if (!ledgerResp.ok) {
    throw new Error(`Stellar : failed to fetch ledger '${transaction.blockId}'`)
  }

  const ledger = (await ledgerResp.json()) as {
    closed_at: string
    sequence: number
  }

  if (!tx.ledger || tx.ledger !== parseInt(transaction.blockId, 10)) {
    throw new Error(
      `Stellar : failed to find 'ledger' field, or it did not match transaction 'blockId' for transaction Id '${transaction.transactionId}'`,
    )
  }

  // console.log(
  //   `Stellar memo '${hexEncode(txMemo)}' for Stellar transaction '${transaction.transactionId
  //   }' matches Truestamp transaction inputHash '${transaction.inputHash
  //   }. See URL : 'https://stellar.expert/explorer/testnet/tx/${transaction.transactionId
  //   }'`,
  // )

  // A browser page with Transaction Details
  // eslint-disable-next-line prettier/prettier
  const urlHuman = `https://stellar.expert/explorer/${testing ? 'testnet' : 'public'}/tx/${transaction.transactionId}`

  const verification: Verification = {
    intent: 'xlm',
    inputHash: transaction.inputHash,
    transactionId: transaction.transactionId,
    blockId: transaction.blockId,
    timestamp: ledger.closed_at,
    urlApi: txUrl,
    urlWeb: urlHuman,
    testing: testing ?? false,
  }

  assert(verification, VerificationStruct)
  return verification
}

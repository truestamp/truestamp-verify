import { encode as hexEncode, decode as hexDecode } from '@stablelib/hex'
import { equal } from '@stablelib/constant-time'
import { decode } from '@stablelib/base64'
import unfetch from 'isomorphic-unfetch'

import { CommitTransactionStellar, VerificationTransaction } from './types'

export async function verifyStellar(transaction: CommitTransactionStellar, testing: boolean | undefined): Promise<VerificationTransaction> {
  const baseUrl = testing ? 'https://horizon-testnet.stellar.org' : 'https://horizon.stellar.org'

  const txUrl = `${baseUrl}/transactions/${transaction.hash}`
  const txResp = await unfetch(txUrl)

  if (!txResp.ok) {
    throw new Error(`Stellar : failed to fetch transaction hash '${transaction.hash}' :  status ${txResp.status} : ${txResp.statusText}`)
  }

  const tx = (await txResp.json()) as {
    memo: string
    memo_type: string
    ledger: number
    successful: boolean
  }

  if (!tx) {
    throw new Error(`Stellar : failed to convert response JSON for transaction hash '${transaction.hash}'`)
  }

  if (!tx.successful) {
    throw new Error(`Stellar : failed to find 'successful' field, or it was false, in response JSON for transaction hash '${transaction.hash}'`)
  }

  if (!tx.memo_type || tx.memo_type !== 'hash') {
    throw new Error(`Stellar : failed to find 'memo_type' field, or it did not have value 'hash', in response JSON for transaction hash '${transaction.hash}'`)
  }

  if (!tx.memo || tx.memo === '') {
    throw new Error(`Stellar : failed to find 'memo' field for transaction hash '${transaction.hash}'`)
  }

  // memo is returned as a base64 encoded string (not url safe string)
  const txMemo = decode(tx.memo)

  if (!equal(txMemo, hexDecode(transaction.inputHash))) {
    throw new Error(
      `Stellar : failed comparing 'memo' to the on-chain 'memo'. Expected '${transaction.inputHash}' but received '${hexEncode(
        txMemo,
      ).toLowerCase()}' from transaction hash '${transaction.hash}'`,
    )
  }

  if (!tx.ledger || tx.ledger !== transaction.ledger) {
    throw new Error(`Stellar : failed to find 'ledger' field, or it did not match transaction 'ledger' for transaction hash '${transaction.hash}'`)
  }

  // Fetch the ledger associated with the transaction, since only the ledger contains the closed_at timestamp.
  const ledgerResp = await unfetch(`${baseUrl}/ledgers/${transaction.ledger}`)

  if (!ledgerResp.ok) {
    throw new Error(`Stellar : failed to fetch ledger '${transaction.ledger}'`)
  }

  const ledger = (await ledgerResp.json()) as {
    closed_at: string
    sequence: number
  }

  if (!tx.ledger || tx.ledger !== transaction.ledger) {
    throw new Error(`Stellar : failed to find 'ledger' field, or it did not match transaction 'ledger' for transaction hash '${transaction.hash}'`)
  }

  // A browser page with Transaction Details

  const urlHumanBase = 'https://stellar.expert/explorer'
  const urlHumanEnv = testing ? 'testnet' : 'public'
  const urlHuman = `${urlHumanBase}/${urlHumanEnv}/tx/${transaction.hash}`

  return VerificationTransaction.parse({
    success: true,
    offline: false,
    intent: 'stellar',
    transaction: transaction,
    timestamp: ledger.closed_at,
    urls: [txUrl, urlHuman],
  })
}

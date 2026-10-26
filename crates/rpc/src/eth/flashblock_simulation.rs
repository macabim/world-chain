//! Signed execution against the requested immutable World Chain prefix.
use super::FlashblocksEthApi;
use alloy_consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_op_evm::OpTx;
use alloy_primitives::{B256, Bytes, U64, U256, keccak256};
use alloy_rpc_types_engine::PayloadId;
use jsonrpsee::{RpcModule, types::ErrorObjectOwned};
use reth_chain_state::BlockState;
use reth_evm::{FromRecoveredTx, TxEnvFor};
use reth_optimism_primitives::OpTransactionSigned as OpTxEnvelope;
use reth_optimism_rpc::OpEthApiError;
use std::sync::Arc;
use world_chain_primitives::primitives::ExecutionPayloadBaseV1;
use world_chain_validator::executed_prefix::{ExecutedPrefix, ExecutedPrefixes};

use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::{Recovered, SignerRecoverable};
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_rpc_eth_api::{
    FromEvmError, RpcConvert, RpcNodeCore,
    helpers::{Call, EthApiSpec, LoadState, SpawnBlocking},
};
use reth_rpc_eth_types::{EthApiError, error::FromEthApiError};
use reth_storage_api::{
    HeaderProvider, ReceiptProvider, StateProviderFactory, TransactionsProvider,
};
use revm::{DatabaseCommit, context_interface::Cfg};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The complete ordered prefix and its immutable execution context.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    chain_id: u64,
    parent_hash: B256,
    payload_id: PayloadId,
    block_number: u64,
    flashblock_index: u64,
    transaction_count: u64,
    transactions_fingerprint: B256,
    block_context_digest: B256,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    identity: Identity,
    deadline_unix_ms: u64,
    simulate_data: Bytes,
    simulate_gas: U64,
    execute_raw_transaction: Bytes,
    prologue_raw_transactions: Vec<Bytes>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Execution {
    success: bool,
    gas_used: U64,
    return_data: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_gas: Option<U64>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    identity: Identity,
    simulate: Execution,
    execute: Execution,
    prefix_expires_at_unix_ms: u64,
}
fn invalid(message: &str) -> OpEthApiError {
    EthApiError::InvalidParams(message.into()).into()
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn check_time(deadline: u64) -> Result<(), OpEthApiError> {
    if now_ms() >= deadline {
        return Err(invalid("flashblock simulation deadline exceeded"));
    }
    Ok(())
}
fn fingerprint<'a>(transactions: impl Iterator<Item = &'a OpTxEnvelope>) -> B256 {
    let mut bytes = Vec::new();
    for tx in transactions {
        let raw = tx.encoded_2718();
        bytes.extend_from_slice(&(raw.len() as u64).to_be_bytes());
        bytes.extend(raw);
    }
    keccak256(bytes)
}
fn context_digest(chain_id: u64, base: &ExecutionPayloadBaseV1) -> B256 {
    let mut bytes = b"MACABIM_FLASHBLOCK_CONTEXT_V1".to_vec();
    bytes.extend(chain_id.to_be_bytes());
    bytes.extend(base.parent_hash);
    bytes.extend(base.fee_recipient);
    bytes.extend(base.prev_randao);
    bytes.extend(base.block_number.to_be_bytes());
    bytes.extend(base.timestamp.to_be_bytes());
    bytes.extend(base.gas_limit.to_be_bytes());
    bytes.extend(base.base_fee_per_gas.to_be_bytes::<32>());
    bytes.extend(base.parent_beacon_block_root);
    bytes.extend((base.extra_data.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&base.extra_data);
    keccak256(bytes)
}
fn identity(chain_id: u64, snapshot: &ExecutedPrefix) -> Identity {
    Identity {
        chain_id,
        parent_hash: snapshot.base.parent_hash,
        payload_id: snapshot.payload_id,
        block_number: snapshot.base.block_number,
        flashblock_index: snapshot.index,
        transaction_count: snapshot.block.recovered_block().body().transactions.len() as u64,
        transactions_fingerprint: fingerprint(
            snapshot.block.recovered_block().body().transactions.iter(),
        ),
        block_context_digest: context_digest(chain_id, &snapshot.base),
    }
}
fn capture(
    cache: Option<&ExecutedPrefixes>,
    requested: &Identity,
) -> Result<Arc<ExecutedPrefix>, OpEthApiError> {
    let snapshot = cache
        .and_then(|cache| {
            cache.get(
                requested.parent_hash,
                requested.payload_id,
                requested.flashblock_index,
            )
        })
        .ok_or_else(|| invalid("requested prefix unavailable"))?;
    if identity(requested.chain_id, &snapshot) != *requested {
        return Err(invalid("requested prefix identity mismatch"));
    }
    Ok(snapshot)
}
fn notification(chain_id: u64, snapshot: &ExecutedPrefix) -> serde_json::Value {
    let block = snapshot.block.recovered_block();
    let mut log_index = 0u64;
    let transactions: Vec<_> = block.body().transactions.iter()
        .zip(&snapshot.block.execution_outcome().receipts).enumerate()
        .map(|(tx_index, (tx, receipt))| {
            let logs: Vec<_> = receipt.logs().iter().map(|log| {
                let value = serde_json::json!({
                    "address": log.address, "topics": log.topics(), "data": log.data.data,
                    "transactionHash": tx.tx_hash(), "transactionIndex": U64::from(tx_index as u64),
                    "blockNumber": U64::from(block.number()), "blockHash": block.hash(),
                    "logIndex": U64::from(log_index), "removed": false
                });
                log_index += 1;
                value
            }).collect();
            serde_json::json!({"hash": tx.tx_hash(), "blockNumber": U64::from(block.number()), "logs": logs})
        }).collect();
    serde_json::json!({
        "number": U64::from(block.number()), "hash": block.hash(),
        "transactions": transactions, "macabimPrefix": identity(chain_id, snapshot)
    })
}
fn decode(raw: &Bytes, chain_id: u64) -> Result<Recovered<OpTxEnvelope>, OpEthApiError> {
    if raw.is_empty() || raw.len() > 131072 {
        return Err(invalid("invalid signed transaction size"));
    }
    let mut slice = raw.as_ref();
    let tx = OpTxEnvelope::decode_2718(&mut slice)
        .map_err(|_| invalid("invalid signed transaction envelope"))?;
    if tx.encoded_2718().as_slice() != raw.as_ref()
        || !slice.is_empty()
        || tx.chain_id() != Some(chain_id)
        || tx.is_deposit()
        || tx.is_post_exec()
    {
        return Err(invalid("transaction chain or envelope is invalid"));
    }
    tx.try_into_recovered()
        .map_err(|_| invalid("invalid transaction signature"))
}
fn ancestor_in_snapshot(snapshot: &ExecutedPrefix, hash: B256) -> Result<bool, OpEthApiError> {
    match snapshot
        .block
        .recovered_block()
        .body()
        .transactions
        .iter()
        .zip(snapshot.block.execution_outcome().receipts.iter())
        .find(|(tx, _)| tx.tx_hash() == hash)
        .map(|(_, receipt)| receipt.status())
    {
        Some(false) => Err(invalid("prologue execution failed")),
        Some(true) => Ok(true),
        None => Ok(false),
    }
}
impl<N, Rpc> FlashblocksEthApi<N, Rpc>
where
    N: RpcNodeCore<Primitives = OpPrimitives>,
    Rpc: RpcConvert<Primitives = OpPrimitives, Error = OpEthApiError, Evm = N::Evm> + Clone,
    OpEthApiError: FromEvmError<N::Evm>,
    TxEnvFor<N::Evm>: From<OpTx>,
{
    /// Register the bounded exact-prefix RPC in the configured Eth module.
    pub fn macabim_module(&self) -> Result<RpcModule<Self>, jsonrpsee::core::RegisterMethodError> {
        let mut module = RpcModule::new(self.clone());
        if self.prefixes.is_none() {
            return Ok(module);
        }
        module.register_async_method(
            "macabim_simulateFlashblockV1",
            |params, api, _| async move {
                let request = params.one::<Request>()?;
                api.simulate_flashblock(request)
                    .await
                    .map_err(ErrorObjectOwned::from)
            },
        )?;
        module.register_subscription(
            "macabim_subscribe", "eth_subscription", "macabim_unsubscribe",
            |params, pending, api, _| async move {
                let Ok(kind) = params.one::<String>() else {
                    pending.reject(ErrorObjectOwned::owned(-32602, "expected newFlashblocks", None::<()>)).await;
                    return Ok(());
                };
                let Some(cache) = api.prefixes.clone().filter(|_| kind == "newFlashblocks") else {
                    pending.reject(ErrorObjectOwned::owned(-32602, "native flashblocks unavailable", None::<()>)).await;
                    return Ok(());
                };
                let mut rx = cache.subscribe();
                let sink = pending.accept().await?;
                loop {
                    let snapshot = rx.borrow_and_update().clone();
                    if let Some(snapshot) = snapshot
                        && api.validate_snapshot(&snapshot, now_ms().saturating_add(1000)).is_ok() {
                            let value = notification(api.chain_id().to::<u64>(), &snapshot);
                            let message = serde_json::value::to_raw_value(&value)?;
                            tokio::select! {
                                _ = sink.closed() => break,
                                sent = tokio::time::timeout(Duration::from_millis(500), sink.send(message)) => {
                                    if !matches!(sent, Ok(Ok(()))) { break; }
                                }
                            }
                    }
                    tokio::select! { _ = sink.closed() => break, changed = rx.changed() => { if changed.is_err() { break; } } }
                }
                Ok(())
            },
        )?;
        Ok(module)
    }
    fn validate_snapshot(
        &self,
        snapshot: &Arc<ExecutedPrefix>,
        deadline: u64,
    ) -> Result<(), OpEthApiError> {
        check_time(deadline)?;
        if !self
            .prefixes
            .as_ref()
            .is_some_and(|cache| cache.contains(snapshot))
        {
            return Err(invalid("native prefix expired or replaced"));
        }
        let base = &snapshot.base;
        let header = snapshot.block.recovered_block().header();
        if header.parent_hash() != base.parent_hash
            || header.number() != base.block_number
            || header.timestamp() != base.timestamp
            || header.gas_limit() != base.gas_limit
            || header.beneficiary() != base.fee_recipient
            || header.mix_hash() != Some(base.prev_randao)
            || header.extra_data() != &base.extra_data
            || header.parent_beacon_block_root() != Some(base.parent_beacon_block_root)
            || U256::from(header.base_fee_per_gas().unwrap_or_default()) != base.base_fee_per_gas
            || snapshot.block.execution_outcome().receipts.len()
                != snapshot.block.recovered_block().body().transactions.len()
        {
            return Err(invalid(
                "native header or receipts do not match captured context",
            ));
        }
        let parent_number = base
            .block_number
            .checked_sub(1)
            .ok_or_else(|| invalid("invalid parent number"))?;
        let parent = self
            .provider()
            .header_by_number(parent_number)?
            .ok_or_else(|| invalid("canonical parent unavailable"))?;
        if parent.hash_slow() != base.parent_hash
            || self
                .provider()
                .header_by_number(base.block_number)?
                .is_some()
        {
            return Err(invalid(
                "canonical parent changed or prefix already canonical",
            ));
        }
        Ok(())
    }
    async fn simulate_flashblock(&self, request: Request) -> Result<Response, OpEthApiError> {
        check_time(request.deadline_unix_ms)?;
        if request.deadline_unix_ms.saturating_sub(now_ms()) > 1000
            || request.prologue_raw_transactions.len() > 16
            || request.simulate_data.len() > 131072
        {
            return Err(invalid("flashblock request bounds exceeded"));
        }
        if request.identity.chain_id != self.chain_id().to::<u64>() {
            return Err(invalid("flashblock chain mismatch"));
        }
        let actual = decode(&request.execute_raw_transaction, request.identity.chain_id)?;
        let ancestors = request
            .prologue_raw_transactions
            .iter()
            .map(|raw| decode(raw, request.identity.chain_id))
            .collect::<Result<Vec<_>, _>>()?;
        let deadline = request.deadline_unix_ms;
        let permit = tokio::time::timeout(
            Duration::from_millis(deadline.saturating_sub(now_ms())),
            self.acquire_owned_blocking_io(),
        )
        .await
        .map_err(|_| invalid("flashblock simulation queue deadline exceeded"))?
        .map_err(|_| invalid("flashblock simulation queue closed"))?;
        self.spawn_blocking_io(move |api| {
            let _permit = permit;
            let snapshot = capture(api.prefixes.as_ref(), &request.identity)?;
            let selected_identity = request.identity.clone();
            api.validate_snapshot(&snapshot, deadline)?;
            let mut native_env =
                api.evm_env_for_header(snapshot.block.recovered_block().sealed_header())?;
            native_env.cfg_env.memory_limit = api.evm_memory_limit();
            let allowance = request
                .simulate_gas
                .to::<u64>()
                .min(snapshot.block.recovered_block().gas_limit())
                .min(api.call_gas_limit())
                .min(native_env.cfg_env.tx_gas_limit_cap());
            if allowance == 0 {
                return Err(invalid("diagnostic gas allowance is zero"));
            }
            let block_gas_remaining = snapshot
                .block
                .recovered_block()
                .gas_limit()
                .saturating_sub(snapshot.block.recovered_block().gas_used());
            let mut results = Vec::with_capacity(2);
            for diagnostic in [true, false] {
                api.validate_snapshot(&snapshot, deadline)?;
                let historical = api
                    .provider()
                    .history_by_block_hash(snapshot.base.parent_hash)
                    .map_err(OpEthApiError::from_eth_err)?;
                let block_state = BlockState::new(snapshot.block.clone());
                let provider = block_state.state_provider(historical);
                let mut db = State::builder()
                    .with_database(StateProviderDatabase::new(provider))
                    .build();
                let mut remaining = block_gas_remaining;
                for ancestor in &ancestors {
                    check_time(deadline)?;
                    if ancestor_in_snapshot(&snapshot, ancestor.tx_hash())? {
                        continue;
                    }
                    if let Some((_, meta)) = api
                        .provider()
                        .transaction_by_hash_with_meta(ancestor.tx_hash())?
                        && meta.block_number < snapshot.block.recovered_block().number()
                    {
                        let receipt = api
                            .provider()
                            .receipt_by_hash(ancestor.tx_hash())?
                            .ok_or_else(|| invalid("prologue receipt unavailable"))?;
                        if !receipt.status() {
                            return Err(invalid("prologue execution failed"));
                        }
                        continue;
                    }
                    if ancestor.gas_limit() > remaining {
                        return Err(invalid("prologue exceeds remaining block gas"));
                    }
                    let tx = OpTx::from_recovered_tx(ancestor.inner(), ancestor.signer()).into();
                    let result = api.transact(&mut db, native_env.clone(), tx)?;
                    if !result.result.is_success() {
                        return Err(invalid("prologue execution failed"));
                    }
                    remaining = remaining.saturating_sub(result.result.tx_gas_used());
                    db.commit(result.state);
                }
                if actual.gas_limit() > remaining {
                    return Err(invalid("execute exceeds remaining block gas"));
                }
                let mut env = native_env.clone();
                let mut tx = OpTx::from_recovered_tx(actual.inner(), actual.signer());
                if diagnostic {
                    tx.base.data = request.simulate_data.clone();
                    tx.base.gas_limit = allowance;
                    env.cfg_env.disable_balance_check = true;
                    env.cfg_env.disable_base_fee = true;
                    env.cfg_env.disable_block_gas_limit = true;
                    env.cfg_env.disable_fee_charge = true;
                }
                let result = api.transact(&mut db, env, tx.into())?;
                results.push(Execution {
                    success: result.result.is_success(),
                    gas_used: U64::from(result.result.tx_gas_used()),
                    return_data: result.result.output().cloned().unwrap_or_default(),
                    tx_hash: (!diagnostic).then(|| actual.tx_hash()),
                    effective_gas: diagnostic.then(|| U64::from(allowance)),
                });
            }
            api.validate_snapshot(&snapshot, deadline)?;
            Ok(Response {
                identity: selected_identity,
                simulate: results.remove(0),
                execute: results.remove(0),
                prefix_expires_at_unix_ms: deadline.min(
                    now_ms().saturating_add(
                        snapshot
                            .expires_at
                            .saturating_duration_since(std::time::Instant::now())
                            .as_millis() as u64,
                    ),
                ),
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_keeps_requested_state_and_rejects_mismatched_identity() {
        let cache = ExecutedPrefixes::default();
        cache.publish(
            Default::default(),
            Default::default(),
            1,
            Default::default(),
        );
        let first = cache.get(B256::ZERO, PayloadId::default(), 1).unwrap();
        let requested = identity(480, &first);
        cache.publish(
            Default::default(),
            Default::default(),
            3,
            Default::default(),
        );
        let captured = capture(Some(&cache), &requested).unwrap();
        assert!(Arc::ptr_eq(&first, &captured));
        let mut wrong = requested.clone();
        wrong.transaction_count += 1;
        assert!(capture(Some(&cache), &wrong).is_err());
        wrong = requested.clone();
        wrong.block_context_digest = B256::repeat_byte(1);
        assert!(capture(Some(&cache), &wrong).is_err());
        wrong = requested.clone();
        wrong.flashblock_index = 2;
        assert!(capture(Some(&cache), &wrong).is_err());
        cache.clear();
        assert!(capture(Some(&cache), &requested).is_err());
    }

    #[test]
    fn matches_independent_viem_fixture() {
        let payload: world_chain_primitives::primitives::FlashblocksPayloadV1<serde_json::Value> =
            serde_json::from_str(include_str!("flashblock_simulation_fixture.json")).unwrap();
        assert_eq!(
            context_digest(8453, payload.base.as_ref().unwrap()),
            "0xac6146019b673dbeab9703481fcae8f7c0bc98ccf44dc40866eed20ba2b7436e"
                .parse::<B256>()
                .unwrap()
        );
        let txs = payload
            .diff
            .transactions
            .iter()
            .map(|raw| {
                let mut bytes = raw.as_ref();
                OpTxEnvelope::decode_2718(&mut bytes).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fingerprint(txs.iter()),
            "0x47bf94109d0d3836a1cc4997c77fe59b765d329146c952ee0a626aebc866c949"
                .parse::<B256>()
                .unwrap()
        );
    }
    fn signed() -> Recovered<OpTxEnvelope> {
        decode(
            &include_str!("flashblock_simulation_signed.txt")
                .trim()
                .parse::<Bytes>()
                .unwrap(),
            8453,
        )
        .unwrap()
    }
    fn native_test_env() -> reth_evm::EvmEnv<op_revm::OpSpecId> {
        let mut cfg = revm::context::CfgEnv::new_with_spec(op_revm::OpSpecId::BEDROCK);
        cfg.chain_id = 8453;
        reth_evm::EvmEnv::new(
            cfg,
            revm::context::BlockEnv {
                gas_limit: 30_000_000,
                basefee: 1,
                ..Default::default()
            },
        )
    }
    fn native_test_db(tx: &Recovered<OpTxEnvelope>) -> revm::database::InMemoryDB {
        let mut db = revm::database::InMemoryDB::default();
        db.insert_account_info(
            tx.signer(),
            revm::state::AccountInfo {
                balance: U256::MAX,
                nonce: tx.nonce(),
                ..Default::default()
            },
        );
        let code = revm::bytecode::Bytecode::new_raw(
            "0x60003560005560005460005260206000f3"
                .parse::<Bytes>()
                .unwrap(),
        );
        db.insert_account_info(
            tx.to().unwrap(),
            revm::state::AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
                ..Default::default()
            },
        );
        db
    }
    #[test]
    fn native_signed_envelope_validates_nonce_balance_and_fee() {
        use reth_evm::{Evm, EvmFactory};
        let signed = signed();
        let tx = OpTx::from_recovered_tx(signed.inner(), signed.signer());
        assert_eq!(
            tx.enveloped_tx.as_ref().unwrap().as_ref(),
            signed.encoded_2718().as_slice()
        );
        let factory = alloy_op_evm::OpEvmFactory::<OpTx>::default();
        assert!(
            factory
                .create_evm(native_test_db(&signed), native_test_env())
                .transact(tx.clone())
                .unwrap()
                .result
                .is_success()
        );
        let mut wrong_nonce = tx.clone();
        wrong_nonce.base.nonce += 1;
        assert!(
            factory
                .create_evm(native_test_db(&signed), native_test_env())
                .transact(wrong_nonce)
                .is_err()
        );
        let mut poor = native_test_db(&signed);
        poor.insert_account_info(
            signed.signer(),
            revm::state::AccountInfo {
                nonce: signed.nonce(),
                ..Default::default()
            },
        );
        assert!(
            factory
                .create_evm(poor, native_test_env())
                .transact(tx.clone())
                .is_err()
        );
        let mut high_fee = native_test_env();
        high_fee.block_env.basefee = signed.max_fee_per_gas() as u64 + 1;
        assert!(
            factory
                .create_evm(native_test_db(&signed), high_fee)
                .transact(tx)
                .is_err()
        );
    }
    #[test]
    fn diagnostic_changes_do_not_enter_execute_fork() {
        use reth_evm::{Evm, EvmFactory};
        let signed = signed();
        let native = OpTx::from_recovered_tx(signed.inner(), signed.signer());
        let db = native_test_db(&signed);
        let factory = alloy_op_evm::OpEvmFactory::<OpTx>::default();
        let mut diagnostic = native.clone();
        diagnostic.base.data = Bytes::from(vec![0x11; 32]);
        let diagnostic_result = factory
            .create_evm(db.clone(), native_test_env())
            .transact(diagnostic)
            .unwrap();
        let actual_result = factory
            .create_evm(db, native_test_env())
            .transact(native)
            .unwrap();
        assert!(diagnostic_result.result.is_success());
        assert!(actual_result.result.is_success());
        assert_ne!(
            diagnostic_result.result.output(),
            actual_result.result.output()
        );
        assert_ne!(
            diagnostic_result.state[&signed.to().unwrap()].storage[&U256::ZERO].present_value(),
            actual_result.state[&signed.to().unwrap()].storage[&U256::ZERO].present_value()
        );
    }
    #[test]
    fn prologue_revert_and_nonce_conflict_fail() {
        use reth_evm::{Evm, EvmFactory};
        let signed = signed();
        let tx = OpTx::from_recovered_tx(signed.inner(), signed.signer());
        let factory = alloy_op_evm::OpEvmFactory::<OpTx>::default();
        let mut db = native_test_db(&signed);
        let code = revm::bytecode::Bytecode::new_raw("0x60006000fd".parse::<Bytes>().unwrap());
        db.insert_account_info(
            signed.to().unwrap(),
            revm::state::AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
                ..Default::default()
            },
        );
        assert!(
            !factory
                .create_evm(db, native_test_env())
                .transact(tx.clone())
                .unwrap()
                .result
                .is_success()
        );
        let mut db = native_test_db(&signed);
        let result = factory
            .create_evm(&mut db, native_test_env())
            .transact(tx.clone())
            .unwrap();
        db.commit(result.state);
        assert!(
            factory
                .create_evm(db, native_test_env())
                .transact(tx)
                .is_err()
        );
    }
    #[tokio::test]
    async fn queue_wait_obeys_deadline() {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let _held = gate.clone().acquire_owned().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(1), gate.acquire_owned())
                .await
                .is_err()
        );
        assert!(check_time(now_ms()).is_err());
    }
    #[test]
    fn signed_decoder_rejects_chain_and_trailing_data() {
        let raw = include_str!("flashblock_simulation_signed.txt")
            .trim()
            .parse::<Bytes>()
            .unwrap();
        assert!(decode(&raw, 130).is_err());
        let mut trailing = raw.to_vec();
        trailing.push(0);
        assert!(decode(&trailing.into(), 8453).is_err());
    }
    #[test]
    fn context_binds_every_field() {
        let base = ExecutionPayloadBaseV1::default();
        let original = context_digest(130, &base);
        let mut changed = base.clone();
        changed.timestamp = 1;
        assert_ne!(original, context_digest(130, &changed));
        assert_ne!(original, context_digest(131, &base));
        changed = base.clone();
        changed.extra_data = Bytes::from_static(&[1]);
        assert_ne!(original, context_digest(130, &changed));
    }
    #[test]
    fn empty_prefix_has_keccak_empty() {
        assert_eq!(fingerprint(std::iter::empty()), keccak256([]));
    }
    #[test]
    fn request_rejects_unsigned_actual_fields() {
        assert!(serde_json::from_str::<Request>(r#"{"executeTransaction":{}}"#).is_err());
    }
}

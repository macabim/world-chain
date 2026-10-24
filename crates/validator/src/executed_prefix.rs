//! Bounded immutable executed prefixes; notifications may coalesce safely.
use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadId;
use parking_lot::RwLock;
use reth_chain_state::ExecutedBlock;
use reth_optimism_primitives::OpPrimitives;
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;
use world_chain_primitives::primitives::ExecutionPayloadBaseV1;

/// One validated cumulative prefix and its execution state.
#[derive(Debug, Clone)]
pub struct ExecutedPrefix {
    pub base: ExecutionPayloadBaseV1,
    pub payload_id: PayloadId,
    pub index: u64,
    pub block: ExecutedBlock<OpPrimitives>,
    pub expires_at: Instant,
}

/// Retains at most sixteen prefixes for two seconds, on one active payload.
#[derive(Debug, Clone)]
pub struct ExecutedPrefixes {
    entries: Arc<RwLock<VecDeque<Arc<ExecutedPrefix>>>>,
    latest: watch::Sender<Option<Arc<ExecutedPrefix>>>,
}

impl Default for ExecutedPrefixes {
    fn default() -> Self {
        Self {
            entries: Default::default(),
            latest: watch::channel(None).0,
        }
    }
}

impl ExecutedPrefixes {
    pub fn subscribe(&self) -> watch::Receiver<Option<Arc<ExecutedPrefix>>> {
        self.latest.subscribe()
    }

    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
        self.latest.send_replace(None);
    }

    pub fn publish(
        &self,
        base: ExecutionPayloadBaseV1,
        payload_id: PayloadId,
        index: u64,
        block: ExecutedBlock<OpPrimitives>,
    ) {
        let mut entries = self.entries.write();
        if entries
            .back()
            .is_some_and(|p| p.base.parent_hash != base.parent_hash || p.payload_id != payload_id)
        {
            entries.clear();
        }
        let now = Instant::now();
        entries.retain(|p| p.expires_at > now);
        let prefix = Arc::new(ExecutedPrefix {
            base,
            payload_id,
            index,
            block,
            expires_at: now + Duration::from_secs(2),
        });
        entries.push_back(prefix.clone());
        while entries.len() > 16 {
            entries.pop_front();
        }
        self.latest.send_replace(Some(prefix));
    }

    pub fn get(&self, parent: B256, payload: PayloadId, index: u64) -> Option<Arc<ExecutedPrefix>> {
        self.entries
            .read()
            .iter()
            .find(|p| {
                p.base.parent_hash == parent
                    && p.payload_id == payload
                    && p.index == index
                    && p.expires_at > Instant::now()
            })
            .cloned()
    }

    pub fn contains(&self, prefix: &Arc<ExecutedPrefix>) -> bool {
        prefix.expires_at > Instant::now()
            && self.entries.read().iter().any(|p| Arc::ptr_eq(p, prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lookup_never_substitutes_latest_and_expiry_invalidates_captured_state() {
        let cache = ExecutedPrefixes::default();
        cache.publish(
            Default::default(),
            Default::default(),
            1,
            Default::default(),
        );
        let first = cache
            .get(B256::ZERO, PayloadId::default(), 1)
            .expect("first");
        cache.publish(
            Default::default(),
            Default::default(),
            3,
            Default::default(),
        );
        assert!(cache.contains(&first));
        assert!(cache.get(B256::ZERO, PayloadId::default(), 2).is_none());
        assert!(Arc::ptr_eq(
            &first,
            &cache
                .get(B256::ZERO, PayloadId::default(), 1)
                .expect("exact")
        ));
        cache.entries.write().clear();
        assert!(!cache.contains(&first));
        let expired = Arc::new(ExecutedPrefix {
            expires_at: Instant::now(),
            ..(*first).clone()
        });
        cache.entries.write().push_back(expired.clone());
        assert!(!cache.contains(&expired));
        assert!(cache.get(B256::ZERO, PayloadId::default(), 1).is_none());
    }
    #[test]
    fn retains_coalesced_prefixes_and_invalidates_replacements() {
        let cache = ExecutedPrefixes::default();
        let rx = cache.subscribe();
        for index in 0..20 {
            cache.publish(
                Default::default(),
                Default::default(),
                index,
                Default::default(),
            );
        }
        assert!(cache.get(B256::ZERO, PayloadId::default(), 0).is_none());
        let old = cache
            .get(B256::ZERO, PayloadId::default(), 4)
            .expect("retained prefix");
        assert_eq!(rx.borrow().as_ref().expect("latest").index, 19);
        let base = ExecutionPayloadBaseV1 {
            parent_hash: B256::repeat_byte(1),
            ..Default::default()
        };
        cache.publish(base, Default::default(), 0, Default::default());
        assert!(!cache.contains(&old));
        cache.clear();
        assert!(rx.borrow().is_none());
    }
}

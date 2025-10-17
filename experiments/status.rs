
// testing some stuff

#![forbid(unsafe_code)]
use crate::spend_builder::AmountZat;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentStatus {
    InProgress { funding_txid: String },
    Finalizing { sweep_txid: String },
    Finalized { sweep_txid: String },
    Canceled,
}

#[derive(Clone, Debug)]
pub struct OutboundRecord {
    pub id: u64,
    pub idx: u32,                // payment index
    pub uri: String,             // capability uri
    pub amount_zat: AmountZat,   // display amount
    pub status: PaymentStatus,
}

pub trait StatusDb: Send + Sync {
    fn next_payment_index(&self) -> anyhow::Result<u32>;
    fn put_outbound(&self, rec: OutboundRecord) -> anyhow::Result<()>;
    fn update_status(&self, id: u64, status: PaymentStatus) -> anyhow::Result<()>;
    fn list_pending(&self) -> anyhow::Result<Vec<OutboundRecord>>;
}

// Minimal in-memory StatusDb for smoke testing
#[derive(Default)]
pub struct InMemoryStatusDb {
    next_idx: std::sync::atomic::AtomicU32,
    recs: std::sync::Mutex<std::collections::HashMap<u64, OutboundRecord>>,
}

impl core::fmt::Debug for InMemoryStatusDb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InMemoryStatusDb").finish()
    }
}

impl StatusDb for InMemoryStatusDb {
    fn next_payment_index(&self) -> anyhow::Result<u32> {
        Ok(self.next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    fn put_outbound(&self, rec: OutboundRecord) -> anyhow::Result<()> {
        let mut guard = self
            .recs
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?;
        guard.insert(rec.id, rec);
        Ok(())
    }

    fn update_status(&self, id: u64, status: PaymentStatus) -> anyhow::Result<()> {
        let mut guard = self
            .recs
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?;
        if let Some(r) = guard.get_mut(&id) {
            r.status = status;
        }
        Ok(())
    }

    fn list_pending(&self) -> anyhow::Result<Vec<OutboundRecord>> {
        let guard = self
            .recs
            .lock()
            .map_err(|_| anyhow::anyhow!("lock poisoned"))?;
        Ok(
            guard
                .values()
                .filter(|r| {
                    !matches!(r.status, PaymentStatus::Finalized { .. } | PaymentStatus::Canceled)
                })
                .cloned()
                .collect(),
        )
    }
}
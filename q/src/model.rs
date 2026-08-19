use serde::Serialize;
use uuid::Uuid;

/// Delivery lifecycle status; maps to the `deliveries.status` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    InFlight,
    Delivered,
    DeadLetter,
}

impl DeliveryStatus {
    /// Stable string form used in the database and wire responses.
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryStatus::Pending => "pending",
            DeliveryStatus::InFlight => "in_flight",
            DeliveryStatus::Delivered => "delivered",
            DeliveryStatus::DeadLetter => "dead_letter",
        }
    }

    /// Parse the database/wire string form.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "in_flight" => Some(Self::InFlight),
            "delivered" => Some(Self::Delivered),
            "dead_letter" => Some(Self::DeadLetter),
            _ => None,
        }
    }
}

/// A row from the `deliveries` table (PLAN.md §5).
#[derive(Debug, Clone, Serialize)]
pub struct Delivery {
    pub id: Uuid,
    pub idempotency_key: Option<String>,
    pub destination: String,
    /// Raw JSON of the submitted `data`.
    pub payload: Vec<u8>,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    /// Unix epoch ms.
    pub next_retry_at: i64,
    pub last_error: Option<String>,
    /// Unix epoch ms.
    pub created_at: i64,
    /// Unix epoch ms.
    pub updated_at: i64,
}

/// Input for [`crate::db::Db::insert`].
#[derive(Debug, Clone)]
pub struct NewDelivery {
    pub id: Uuid,
    pub idempotency_key: Option<String>,
    pub destination: String,
    /// Raw JSON of the submitted `data`.
    pub payload: Vec<u8>,
    pub max_attempts: u32,
}

/// A row from the `dead_letters` table (PLAN.md §5).
#[derive(Debug, Clone, Serialize)]
pub struct DlqEntry {
    /// DLQ entry id (fresh uuid, not the delivery id).
    pub id: Uuid,
    pub delivery_id: String,
    pub destination: String,
    pub payload: Vec<u8>,
    pub attempts: u32,
    pub last_error: Option<String>,
    /// Unix epoch ms.
    pub dead_lettered_at: i64,
}

/// Queue counters (PLAN.md §5 `stats()`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub submitted: u64,
    pub delivered: u64,
    pub dead_lettered: u64,
    pub pending: u64,
    pub in_flight: u64,
    pub dead_letters: u64,
}

/// Current wall-clock time as Unix epoch milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

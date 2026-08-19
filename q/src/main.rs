//! webhook-delivery binary entry point (PLAN.md, T9/T10).

#[tokio::main]
async fn main() {
    webhook_delivery::run().await;
}

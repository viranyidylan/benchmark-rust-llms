//! Exponential backoff with full jitter (PLAN.md, T3).

use rand::RngCore;

/// Uniform random value in `0..=cap` from a bare [`RngCore`].
///
/// rand 0.8's `RngCore` has no `random_range`, so sample 64 bits and reduce
/// modulo `cap + 1`. The modulo bias is bounded by `1/(cap+1) <= 2^-64`,
/// negligible for backoff jitter.
fn uniform_inclusive(rng: &mut impl RngCore, cap: u64) -> u64 {
    if cap == u64::MAX {
        rng.next_u64()
    } else {
        rng.next_u64() % (cap + 1)
    }
}

/// Compute the delay before the next retry attempt.
///
/// Full jitter (PLAN.md §5): the exponent is `(attempt - 1)` capped at 20,
/// `cap = min(base_ms * 2^exp, max_ms)`, and the returned delay is uniformly
/// random in `0..=cap`. `attempt` is 1-based (1 = first retry).
pub fn next_delay_ms(attempt: u32, base_ms: u64, max_ms: u64, rng: &mut impl RngCore) -> u64 {
    let exp = attempt.saturating_sub(1).min(20);
    let cap = base_ms.checked_shl(exp).unwrap_or(u64::MAX).min(max_ms);
    uniform_inclusive(rng, cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn cap_for(attempt: u32, base: u64, max: u64) -> u64 {
        let exp = (attempt - 1).min(20);
        base.checked_shl(exp).unwrap_or(u64::MAX).min(max)
    }

    #[test]
    fn jitter_within_bounds_and_positive() {
        let mut rng = StdRng::seed_from_u64(42);
        let base = 5_000u64;
        let max = 60_000u64;
        for attempt in 1..=25u32 {
            let cap = cap_for(attempt, base, max);
            let mut any_positive = false;
            for _ in 0..10_000 {
                let d = next_delay_ms(attempt, base, max, &mut rng);
                assert!(d <= cap, "delay {d} exceeds cap {cap} (attempt {attempt})");
                if d > 0 {
                    any_positive = true;
                }
            }
            assert!(
                any_positive,
                "no positive delay across 10k samples at attempt {attempt}"
            );
        }
    }

    #[test]
    fn cap_respected_at_high_attempts() {
        let mut rng = StdRng::seed_from_u64(7);
        let base = 5_000u64;
        let max = 60_000u64;
        // `base * 2^20` far exceeds `max`, so from attempt 21 on the cap is `max`.
        for attempt in [20u32, 21, 22, 50, 1_000] {
            for _ in 0..1_000 {
                assert!(next_delay_ms(attempt, base, max, &mut rng) <= max);
            }
        }
    }

    #[test]
    fn first_retry_caps_at_base() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..1_000 {
            assert!(next_delay_ms(1, 5_000, 60_000, &mut rng) <= 5_000);
        }
    }
}

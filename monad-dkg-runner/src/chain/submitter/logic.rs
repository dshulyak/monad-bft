use monad_eth_types::buffered_base_fee_per_gas;
use monad_types::Nonce;

use super::super::DkgTransactionContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PreparedTransaction {
    pub(super) nonce: Nonce,
    pub(super) max_fee_per_gas: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RefreshDecision {
    Obsolete,
    Keep,
    Prepare { max_fee_per_gas: u128 },
}

pub(super) fn decide_refresh(
    prepared: Option<PreparedTransaction>,
    context: DkgTransactionContext,
    max_priority_fee_per_gas: u128,
) -> RefreshDecision {
    let max_fee_per_gas = buffered_base_fee_per_gas(u128::from(context.base_fee_per_gas))
        .saturating_add(max_priority_fee_per_gas);
    let Some(prepared) = prepared else {
        return RefreshDecision::Prepare { max_fee_per_gas };
    };
    if prepared.nonce < context.nonce {
        return RefreshDecision::Obsolete;
    }
    if prepared.nonce != context.nonce || prepared.max_fee_per_gas >= max_fee_per_gas {
        return RefreshDecision::Keep;
    }
    RefreshDecision::Prepare { max_fee_per_gas }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_decision_uses_only_transaction_context() {
        let context = DkgTransactionContext {
            nonce: 4,
            base_fee_per_gas: 100,
        };

        assert!(matches!(
            decide_refresh(None, context, 1),
            RefreshDecision::Prepare { .. }
        ));
        assert_eq!(
            decide_refresh(
                Some(PreparedTransaction {
                    nonce: 3,
                    max_fee_per_gas: u128::MAX,
                }),
                context,
                1,
            ),
            RefreshDecision::Obsolete
        );
        assert_eq!(
            decide_refresh(
                Some(PreparedTransaction {
                    nonce: 5,
                    max_fee_per_gas: 0,
                }),
                context,
                1,
            ),
            RefreshDecision::Keep
        );
    }
}

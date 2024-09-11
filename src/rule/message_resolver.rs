use crate::rule::rule_result::RuleResultDetail;

/// Strategy pattern interface for resolving messages from password validation failures described
/// by a RuleResultDetail object.
pub trait MessageResolver {
    /// Resolves the message for the supplied rule result detail.
    fn resolve(&self, detail: &RuleResultDetail) -> String;
}

pub struct DebugMessageResolver;

impl MessageResolver for DebugMessageResolver {
    fn resolve(&self, detail: &RuleResultDetail) -> String {
        format!("{detail:?}")
    }
}

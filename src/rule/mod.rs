use std::fmt::Display;

use crate::rule::reference::{Reference, VoidReference};
use crate::rule::rule_result::RuleResult;

mod length_rule;
mod reference;
mod rule_result;

pub trait Rule {
    fn validate(&self, password_data: PasswordData<impl Reference>) -> RuleResult;
}

/// Contains password related information used by rules to perform password validation.
pub struct PasswordData<R>
where
    R: Reference,
{
    password: String,
    username: Option<String>,
    password_references: Vec<R>,
}

impl PasswordData<VoidReference> {
    pub fn new(password: String) -> Self {
        Self {
            password,
            username: None,
            password_references: Vec::<VoidReference>::new(),
        }
    }
}

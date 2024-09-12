use crate::rule::reference::Reference;
use crate::rule::rule_result::RuleResult;

mod character_sequence;
mod illegal_regex;
mod illegal_sequence_rule;
mod length_rule;
pub mod message_resolver;
mod password_validator;
mod reference;
pub mod rule_result;
mod sequence_data;

pub trait Rule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult;
}

/// Contains password related information used by rules to perform password validation.
#[derive(Debug)]
pub struct PasswordData {
    password: String,
    username: Option<String>,
    password_references: Vec<Box<dyn Reference>>,
}

impl PasswordData {
    pub fn new(password: String) -> Self {
        Self {
            password,
            username: None,
            password_references: Vec::new(),
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

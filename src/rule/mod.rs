use crate::rule::reference::Reference;
use crate::rule::rule_result::RuleResult;

mod allowed_character;
mod allowed_regex;
mod character;
mod character_characteristics;
mod character_data;
mod character_occurrences;
mod character_sequence;
mod dictionary;
mod dictionary_substring;
mod digest_dictionary;
mod digest_history;
mod history;
mod illegal_regex;
mod illegal_sequence_rule;
mod length_rule;
pub mod message_resolver;
mod password_utils;
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
    pub fn with_password(password: String) -> Self {
        Self {
            password,
            username: None,
            password_references: Vec::new(),
        }
    }
    pub fn with_password_and_user(password: String, username: Option<String>) -> Self {
        Self {
            password,
            username,
            password_references: Vec::new(),
        }
    }
    pub fn new(
        password: String,
        username: Option<String>,
        password_references: Vec<Box<dyn Reference>>,
    ) -> Self {
        Self {
            password,
            username,
            password_references,
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn password_references(&self) -> &Vec<Box<dyn Reference>> {
        &self.password_references
    }
}

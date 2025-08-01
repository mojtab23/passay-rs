use crate::dictionary::Dictionary;
use crate::rule::reference::Reference;
use crate::rule::rule_result::RuleResult;

pub mod allowed_character;
mod allowed_regex;
pub mod character;
pub mod character_characteristics;
pub mod character_data;
mod character_occurrences;
mod character_sequence;
pub(crate) mod dictionary;
mod dictionary_substring;
mod digest_dictionary;
mod digest_history;
mod digest_source;
mod history;
mod illegal_character;
mod illegal_regex;
mod illegal_sequence_rule;
mod length_complexity;
pub mod length_rule;
pub mod message_resolver;
mod number_range;
mod password_utils;
pub mod password_validator;
mod reference;
mod repeat_character_regex;
mod repeat_characters;
pub mod rule_result;
mod sequence_data;
mod source;
mod username;
mod whitespace;

pub trait Rule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult;
    fn as_has_characters<'a>(&'a self) -> Option<&'a dyn HasCharacters> {
        None
    }
    fn as_dictionary_rule<'a>(&'a self) -> Option<&'a dyn DictionaryRuleTrait> {
        None
    }
}

pub trait HasCharacters: Rule {
    fn characters(&self) -> String;
}

pub trait DictionaryRuleTrait: Rule {
    fn dictionary(&self) -> &dyn Dictionary;
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

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
}

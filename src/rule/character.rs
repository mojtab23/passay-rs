use crate::rule::character_data::CharacterData;
use crate::rule::password_utils::{count_matching_characters, get_matching_characters};
use crate::rule::rule_result::{RuleResult, RuleResultDetail, RuleResultMetadata};
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;

pub struct CharacterRule {
    character_data: Box<dyn CharacterData>,
    num_characters: usize,
}

impl CharacterRule {
    pub fn new(
        character_data: Box<dyn CharacterData>,
        num_characters: usize,
    ) -> Result<CharacterRule, String> {
        if num_characters < 1 {
            return Err(String::from(
                "Number of characters must be greater than zero",
            ));
        }
        Ok(CharacterRule {
            character_data,
            num_characters,
        })
    }
    pub fn from_character_data(character_data: Box<dyn CharacterData>) -> CharacterRule {
        CharacterRule {
            character_data,
            num_characters: 1,
        }
    }
    fn create_rule_result_detail_parameters(
        &self,
        matching_chars: String,
    ) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(4);
        map.insert(
            "minimumRequired".to_string(),
            self.num_characters.to_string(),
        );
        map.insert(
            "matchingCharacterCount".to_string(),
            matching_chars.len().to_string(),
        );
        map.insert(
            "validCharacters".to_string(),
            self.character_data.characters().to_string(),
        );
        map.insert("matchingCharacters".to_string(), matching_chars);
        map
    }
    pub fn create_rule_result_metadata(&self, password_data: &PasswordData) -> RuleResultMetadata {
        if let Some(cc) = self.character_data.count_category() {
            return RuleResultMetadata::new(
                cc,
                count_matching_characters(
                    self.character_data.characters(),
                    password_data.password(),
                ),
            );
        }
        RuleResultMetadata::default()
    }
}

impl Rule for CharacterRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let matching_chars = get_matching_characters(
            self.character_data.characters(),
            password_data.password(),
            self.num_characters,
        );
        if matching_chars.len() < self.num_characters {
            let mut result = RuleResult::new(false);
            let detail = RuleResultDetail::new(
                vec![self.character_data.error_code().to_string()],
                Some(self.create_rule_result_detail_parameters(matching_chars)),
            );
            result.details_mut().push(detail);
            result.set_metadata(self.create_rule_result_metadata(password_data));
            result
        } else {
            let mut result = RuleResult::default();
            result.set_metadata(self.create_rule_result_metadata(password_data));
            result
        }
    }
}

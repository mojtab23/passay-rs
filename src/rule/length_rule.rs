use std::collections::HashMap;

use crate::rule::rule_result::{CountCategory, RuleResult, RuleResultMetadata};
use crate::rule::{PasswordData, Rule};

pub const ERROR_CODE_MIN: &str = "TOO_SHORT";
pub const ERROR_CODE_MAX: &str = "TOO_LONG";
pub struct LengthRule {
    min_length: usize,
    max_length: usize,
}

impl LengthRule {
    pub fn new(min_length: usize, max_length: usize) -> Self {
        Self {
            min_length,
            max_length,
        }
    }
    pub fn with_exact_length(length: usize) -> Self {
        Self {
            min_length: length,
            max_length: length,
        }
    }

    fn create_rule_result_detail_parameters(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("min_length".to_string(), self.min_length.to_string());
        map.insert("max_length".to_string(), self.max_length.to_string());
        map
    }
    fn create_rule_result_metadata(password_data: &PasswordData) -> RuleResultMetadata {
        RuleResultMetadata::new(CountCategory::Length, password_data.password.len())
    }
}

impl Default for LengthRule {
    fn default() -> Self {
        LengthRule {
            min_length: 0,
            max_length: usize::MAX,
        }
    }
}

impl Rule for LengthRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::new(true);
        let length = password_data.password.len();
        if length < self.min_length {
            result.add_error(
                ERROR_CODE_MIN,
                Some(self.create_rule_result_detail_parameters()),
            );
        } else if length > self.max_length {
            result.add_error(
                ERROR_CODE_MAX,
                Some(self.create_rule_result_detail_parameters()),
            )
        }
        result.set_metadata(Self::create_rule_result_metadata(password_data));
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::length_rule::LengthRule;
    use crate::rule::rule_result::CountCategory;
    use crate::rule::{PasswordData, Rule};

    #[test]
    fn check_metadata() {
        let rule = LengthRule::new(4, 10);
        let result = rule.validate(&PasswordData::with_password("metadata".to_string()));
        assert!(result.valid());
        assert_eq!(
            8,
            result.metadata().get_count(CountCategory::Length).unwrap()
        );

        let result = rule.validate(&PasswordData::with_password("md".to_string()));
        assert!(!result.valid());
        assert_eq!(
            2,
            result.metadata().get_count(CountCategory::Length).unwrap()
        );
    }
}

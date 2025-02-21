use crate::rule::allowed_character::MatchBehavior;
use crate::rule::allowed_character::MatchBehavior::Contains;
use crate::rule::password_utils::count_matching_characters;
use crate::rule::rule_result::{CountCategory, RuleResult, RuleResultMetadata};
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;

const ERROR_CODE: &str = "ILLEGAL_WHITESPACE";
const WHITESPACES: &[char] =
    &['\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}'];
pub struct WhitespaceRule {
    report_rule_failures: bool,
    whitespace_chars: Vec<char>,
    match_behavior: MatchBehavior,
}

impl WhitespaceRule {
    pub fn new(
        chars: Vec<char>,
        match_behavior: MatchBehavior,
        report_rule_failures: bool,
    ) -> WhitespaceRule {
        for ch in chars.iter() {
            if !ch.is_whitespace() {
                panic!("Character '{}' is not whitespace", ch);
            }
        }
        WhitespaceRule {
            whitespace_chars: chars.to_vec(),
            match_behavior,
            report_rule_failures,
        }
    }
    pub fn with_behavior(
        match_behavior: MatchBehavior,
        report_rule_failures: bool,
    ) -> WhitespaceRule {
        Self::new(WHITESPACES.to_vec(), match_behavior, report_rule_failures)
    }

    fn create_rule_result_detail_parameters(&self, c: char) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(2);
        map.insert("whitespaceCharacter".to_string(), c.to_string());
        map.insert(
            "matchBehavior".to_string(),
            format!("{:?}", self.match_behavior),
        );
        map
    }

    pub fn create_rule_result_metadata(&self, password_data: &PasswordData) -> RuleResultMetadata {
        RuleResultMetadata::new(
            CountCategory::Whitespace,
            count_matching_characters(
                self.whitespace_chars.iter().collect::<String>().as_str(),
                password_data.password(),
            ),
        )
    }
}

impl Rule for WhitespaceRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let text = password_data.password();
        for c in &self.whitespace_chars {
            if self.match_behavior.match_char(text, *c) {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters(*c)),
                );
                if !self.report_rule_failures {
                    break;
                }
            }
        }
        result.set_metadata(self.create_rule_result_metadata(password_data));
        result
    }
}

impl Default for WhitespaceRule {
    fn default() -> WhitespaceRule {
        WhitespaceRule::new(WHITESPACES.to_vec(), Contains, true)
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::allowed_character::MatchBehavior::{Contains, EndsWith, StartsWith};
    use crate::rule::rule_result::CountCategory;
    use crate::rule::whitespace::{WhitespaceRule, ERROR_CODE};
    use crate::rule::{PasswordData, Rule};
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycDPdsyz".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycD Pdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycD Pds\tyz".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("Ayc\tDPdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycD\nPdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycD\rPdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycD\n\rPdsyz".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::with_behavior(Contains, false)),
                PasswordData::with_password("AycD\n\rPdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::with_behavior(StartsWith, true)),
                PasswordData::with_password(" AycDPdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::with_behavior(StartsWith, true)),
                PasswordData::with_password("AycD Pdsyz".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::with_behavior(EndsWith, true)),
                PasswordData::with_password("AycDPdsyz ".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::with_behavior(EndsWith, true)),
                PasswordData::with_password("AycDPd syz".to_string()),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(WhitespaceRule::with_behavior(StartsWith, true)),
                PasswordData::with_password("\tAycDPdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(WhitespaceRule::default()),
                PasswordData::with_password("AycD Pds\tyz".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
        ];
        check_messages(test_cases);
    }

    #[test]
    fn check_metadata() {
        let rule = WhitespaceRule::default();
        let result = rule.validate(&PasswordData::with_password("metadata".to_string()));
        assert!(result.valid());
        assert_eq!(0, result.metadata().get_count(CountCategory::Whitespace));

        let result = rule.validate(&PasswordData::with_password("meta data".to_string()));
        assert!(!result.valid());
        assert_eq!(1, result.metadata().get_count(CountCategory::Whitespace));
    }

    #[test]
    #[should_panic(expected = "Character 'a' is not whitespace")]
    fn check_valid_characters() {
        let rule = WhitespaceRule::new(vec![' ', 'a'], Contains, true);
    }
}

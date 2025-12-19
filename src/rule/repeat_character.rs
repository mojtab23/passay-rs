use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::{HashMap, HashSet};

pub const ERROR_CODE: &str = "ILLEGAL_MATCH";
const DEFAULT_SEQUENCE_LENGTH: usize = 5;
const MINIMUM_SEQUENCE_LENGTH: usize = 3;

/// Rule for determining if a password contains a duplicate character sequence.
/// The default sequence length is 5 characters.
/// Sequences are of the form: 'bbbbb' or '#####'
///
/// # Example
///
/// ```
///  use passay_rs::rule::PasswordData;
///  use passay_rs::rule::repeat_character::RepeatCharacterRule;
///  use passay_rs::rule::Rule;
///  use fancy_regex::Regex;
///
///  let rule =RepeatCharacterRule::default();
///  let password = PasswordData::with_password("p4&&&&&#n65".to_string());
///  let result = rule.validate(&password);
///  assert!(!result.valid());
/// ```
pub struct RepeatCharacterRule {
    sequence_length: usize,
    report_all: bool,
}

impl RepeatCharacterRule {
    pub fn new(sequence_length: usize, report_all: bool) -> Result<Self, String> {
        if sequence_length < MINIMUM_SEQUENCE_LENGTH {
            return Err(format!(
                "sequence length must be >= {MINIMUM_SEQUENCE_LENGTH}"
            ));
        }
        Ok(Self {
            sequence_length,
            report_all,
        })
    }
    pub fn with_sequence_len(sequence_len: usize) -> Result<Self, String> {
        Self::new(sequence_len, true)
    }

    fn create_rule_result_detail_parameters(&self, match_str: &str) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(2);
        map.insert("match".to_string(), match_str.to_string());
        map.insert(
            "sequence_length".to_string(),
            self.sequence_length.to_string(),
        );
        map
    }
}

impl Rule for RepeatCharacterRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let mut matches = HashSet::new();

        let mut previous_ch = None;
        let mut count = 1;
        let mut matched = false;
        let mut sequence_start_byte = 0; // Track the byte offset of the current sequence

        for (i, ch) in password_data.password.char_indices() {
            if previous_ch.is_none() {
                previous_ch = Some(ch);
                sequence_start_byte = i;
            } else if previous_ch == Some(ch) {
                count += 1;
                if count >= self.sequence_length {
                    matched = true;
                };
            } else {
                if matched {
                    let matched_text = &password_data.password[sequence_start_byte..i];
                    if !matches.contains(matched_text) {
                        result.add_error(
                            ERROR_CODE,
                            Some(self.create_rule_result_detail_parameters(matched_text)),
                        );

                        if !self.report_all {
                            return result;
                        }
                        matches.insert(matched_text);
                    }
                    matched = false;
                }
                previous_ch = Some(ch);
                count = 1;
                sequence_start_byte = i;
            }
        }

        if matched {
            let matched_text = &password_data.password[sequence_start_byte..];

            if !matches.contains(matched_text) {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters(matched_text)),
                );
            }
        }

        result
    }
}

impl Default for RepeatCharacterRule {
    fn default() -> Self {
        RepeatCharacterRule::new(DEFAULT_SEQUENCE_LENGTH, true).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::PasswordData;
    use crate::rule::repeat_character::{ERROR_CODE, RepeatCharacterRule};
    use crate::test::{RulePasswordTestItem, check_messages, check_passwords};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test repeating character
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test longer repeating character
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4vvvvvvv#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test valid password for long regex
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::with_sequence_len(7).unwrap()),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test long regex with short repeat
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::with_sequence_len(7).unwrap()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec![],
            ),
            // test long regex with long repeat
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::with_sequence_len(7).unwrap()),
                PasswordData::with_password("p4vvvvvvv#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test single match
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::new(5, false).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![ERROR_CODE],
            ),
            // test duplicate matches
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFFQr1&&&&&".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test utf8 characters
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("ميييييجتبیيييييي".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
        ];

        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&", "ILLEGAL_MATCH,FFFFF"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::new(5, false).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFFQr1&&&&&".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&", "ILLEGAL_MATCH,FFFFF"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRule::default()),
                PasswordData::with_password("مجتبيييييي".to_string()),
                vec!["ILLEGAL_MATCH,يييييي"],
            ),
        ];
        check_messages(test_cases);
    }
}

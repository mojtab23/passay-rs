use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;

const ERROR_CODE: &str = "ILLEGAL_REPEATED_CHARS";
const DEFAULT_SEQUENCE_LENGTH: usize = 5;
const DEFAULT_SEQUENCE_COUNT: usize = 1;

/// Rule for determining if a password contains multiple sequences of repeating characters.
/// For example, the password "11a22b333xyz" will fail validation of this rule with
/// a sequence length of 2 and sequence count of 3, since it contains 3 sequences (or more)
/// of 2 repeating characters (or more).
///
/// # Example
///
/// ```
///  use passay_rs::rule::PasswordData;
///  use passay_rs::rule::repeat_characters::RepeatCharactersRule;
///  use passay_rs::rule::Rule;
///  use fancy_regex::Regex;
///
///  let rule = RepeatCharactersRule::new(5, 2).unwrap();
///  let password = PasswordData::with_password("p4&&&&&#n65FFFFF".to_string());
///  let result = rule.validate(&password);
///  assert!(!result.valid());
/// ```
pub struct RepeatCharactersRule {
    sequence_length: usize,
    sequence_count: usize,
}

impl RepeatCharactersRule {
    pub fn new(sequence_length: usize, sequence_count: usize) -> Result<Self, String> {
        if sequence_count < 1 {
            return Err("sequence count must be > 0".into());
        }
        if sequence_length < 2 {
            return Err("sequence length must be > 2".into());
        }

        Ok(Self {
            sequence_length,
            sequence_count,
        })
    }
    pub fn with_sequence_length(sequence_length: usize) -> Result<Self, String> {
        Self::new(sequence_length, DEFAULT_SEQUENCE_COUNT)
    }

    fn create_rule_result_detail_parameters(&self, matches: &[String]) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(4);
        map.insert(
            "sequenceLength".to_string(),
            self.sequence_length.to_string(),
        );
        map.insert("sequenceCount".to_string(), self.sequence_count.to_string());
        map.insert("matchesCount".to_string(), matches.len().to_string());
        map.insert("matches".to_string(), matches.join(","));
        map
    }
}

impl Default for RepeatCharactersRule {
    fn default() -> Self {
        Self::new(DEFAULT_SEQUENCE_LENGTH, DEFAULT_SEQUENCE_COUNT).unwrap()
    }
}

impl Rule for RepeatCharactersRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let mut matches = vec![];
        let password = format!("{}{}", password_data.password(), '\u{ffff}');
        let mut count = 0;
        let mut repeat = 1;
        let mut prev: Option<char> = None;
        let chars: Vec<char> = password.chars().collect();
        let max = chars.len() - 1;

        for i in 0..=max {
            let c = chars[i];
            if prev.is_some() && c == prev.unwrap() {
                repeat += 1;
            } else {
                if repeat >= self.sequence_length {
                    let m: String = chars[i - repeat..i].iter().collect();
                    matches.push(m);
                    count += 1;
                }
                repeat = 1;
            }
            prev = Some(c);
        }
        if count >= self.sequence_count {
            result.add_error(
                ERROR_CODE,
                Some(self.create_rule_result_detail_parameters(&matches)),
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::repeat_characters::{RepeatCharactersRule, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::default()),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test repeating character
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::default()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test longer repeating character
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::default()),
                PasswordData::with_password("p4vvvvvvv#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test valid password for long sequence
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::with_sequence_length(7).unwrap()),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test long sequence with short repeat
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::with_sequence_length(7).unwrap()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec![],
            ),
            // test long sequence with long repeat
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::with_sequence_length(7).unwrap()),
                PasswordData::with_password("p4vvvvvvv#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches with allowed count
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::new(5, 3).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![],
            ),
            // test single match when max is two
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::new(5, 2).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFF".to_string()),
                vec![],
            ),
            // test two matches when max is two
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::new(5, 2).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![ERROR_CODE],
            ),
            // test two matches when max is more than two
            RulePasswordTestItem(
                Box::new(RepeatCharactersRule::new(5, 3).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![],
            ),
        ];

        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![RulePasswordTestItem(
            Box::new(RepeatCharactersRule::new(2, 2).unwrap()),
            PasswordData::with_password("paaxvbbdkccx".to_string()),
            vec!["ILLEGAL_REPEATED_CHARS,3,2,2,aa,bb,cc"],
        )];
        check_messages(test_cases);
    }
}

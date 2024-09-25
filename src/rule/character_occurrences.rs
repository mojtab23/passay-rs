use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;

const ERROR_CODE: &str = "TOO_MANY_OCCURRENCES";

#[derive(Debug, Clone)]
pub struct CharacterOccurrences {
    max_occurrences: usize,
}

impl CharacterOccurrences {
    pub fn new(max_occurrences: usize) -> Self {
        Self { max_occurrences }
    }

    fn create_rule_result_detail_parameters(
        &self,
        c: char,
        repeat: usize,
    ) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(3);
        map.insert("matchingCharacter".to_string(), c.to_string());
        map.insert("matchingCharacterCount".to_string(), repeat.to_string());
        map.insert(
            "maximumOccurrences".to_string(),
            self.max_occurrences.to_string(),
        );
        map
    }
}

impl Rule for CharacterOccurrences {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let password = password_data.password().to_string() + "\u{ffff}";
        let mut chars = password.chars().collect::<Vec<char>>();
        chars.sort();

        let mut repeat = 1;
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] {
                repeat += 1;
            } else {
                if repeat > self.max_occurrences {
                    result.add_error(
                        ERROR_CODE,
                        Some(self.create_rule_result_detail_parameters(chars[i - 1], repeat)),
                    )
                }
                repeat = 1;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::character_occurrences::{CharacterOccurrences, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let rule = Box::new(CharacterOccurrences::new(4));
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("p4zRcv101#n6F".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("aaaa#n65".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("a1a2a3a4#n65bbbb".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("aaaaa".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("aaaaa#n65".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("111aaaaa".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("aaaaabbb".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("a1a2a3a4a".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("1aa2aa3a".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("babababab".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                rule.clone(),
                PasswordData::with_password("ababababa".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(CharacterOccurrences::new(5)),
                PasswordData::with_password("1aa2aa3aa4bbb5bb6bbb".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
        ];
        check_passwords(test_cases);
    }
    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![RulePasswordTestItem(
            Box::new(CharacterOccurrences::new(4)),
            PasswordData::with_password("a1a2a3a4a5a".to_string()),
            vec!["TOO_MANY_OCCURRENCES,6,a,4"],
        )];
        check_messages(test_cases);
    }
}

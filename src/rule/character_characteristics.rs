use crate::rule::character::CharacterRule;
use crate::rule::character_data::CharacterData;
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

const ERROR_CODE: &str = "INSUFFICIENT_CHARACTERISTICS";
pub struct CharacterCharacteristics {
    rules: Vec<CharacterRule>,
    num_characteristics: usize,
    report_failure: bool,
    report_rule_failures: bool,
}

impl CharacterCharacteristics {
    pub fn new(
        rules: Vec<CharacterRule>,
        num_characteristics: usize,
        report_failure: bool,
        report_rule_failures: bool,
    ) -> Result<CharacterCharacteristics, String> {
        if num_characteristics < 1 {
            return Err("Number of characteristics must be greater than zero".to_string());
        }
        if num_characteristics > rules.len() {
            return Err("Number of characteristics must be <= to the number of rules".to_string());
        }
        Ok(CharacterCharacteristics {
            rules,
            num_characteristics,
            report_failure,
            report_rule_failures,
        })
    }
    pub fn with_rules_and_characteristics(
        rules: Vec<CharacterRule>,
        num_characteristics: usize,
    ) -> Result<CharacterCharacteristics, String> {
        Self::new(rules, num_characteristics, true, true)
    }
    pub fn from_rules(rules: Vec<CharacterRule>) -> Result<CharacterCharacteristics, String> {
        Self::with_rules_and_characteristics(rules, 1)
    }
    fn create_rule_result_detail_parameters(&self, success: usize) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("successCount".to_string(), success.to_string());
        map.insert(
            "minimumRequired".to_string(),
            self.num_characteristics.to_string(),
        );
        map.insert("ruleCount".to_string(), self.rules.len().to_string());
        map
    }
}

impl Rule for CharacterCharacteristics {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        dbg!(password_data);
        let mut success_count = 0usize;
        let mut result = RuleResult::default();
        for rule in &self.rules {
            let mut rr = rule.validate(password_data);
            if rr.valid() {
                success_count += 1;
            } else {
                if self.report_rule_failures {
                    result.details_mut().append(rr.details_mut())
                }
            }
            result.metadata_mut().merge(rr.metadata())
        }
        if success_count < self.num_characteristics {
            result.set_valid(false);
            if self.report_failure {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters(success_count)),
                )
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::character::CharacterRule;
    use crate::rule::character_characteristics::{CharacterCharacteristics, ERROR_CODE};
    use crate::rule::character_data::{CharacterData, EnglishCharacterData};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // valid ascii password
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r%scvEW2e93)".to_string()),
                vec![],
            ),
            // valid non-ascii password
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r¢sCvE±2e93".to_string()),
                vec![],
            ),
            // issue #32
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r~scvEW2e93b".to_string()),
                vec![],
            ),
            // missing lowercase
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r%5#8EW2393)".to_string()),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Alphabetical.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                ],
            ),
            // missing 3 digits
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r%scvEW2e9e)".to_string()),
                vec![ERROR_CODE, EnglishCharacterData::Digit.error_code()],
            ),
            // missing 2 uppercase
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r%scv3W2e9)".to_string()),
                vec![ERROR_CODE, EnglishCharacterData::UpperCase.error_code()],
            ),
            // missing 2 lowercase
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("R%s4VEW239)".to_string()),
                vec![ERROR_CODE, EnglishCharacterData::LowerCase.error_code()],
            ),
            // missing 1 special
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r5scvEW2e9b".to_string()),
                vec![ERROR_CODE, EnglishCharacterData::Special.error_code()],
            ),
            // previous passwords all valid under different rule set
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("r%scvEW2e93)".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("r¢sCvE±2e93".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("r%5#8EW2393)".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("r%scvEW2e9e)".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("r%scv3W2e9)".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("R%s4VEW239)".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("r5scvEW2e9b".to_string()),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }
    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("r%scvEW2e3)".to_string()),
                vec!["INSUFFICIENT_DIGIT,3,2", "INSUFFICIENT_CHARACTERISTICS,4,5"],
            ),
            RulePasswordTestItem(
                create_rule1(),
                PasswordData::with_password("R»S7VEW2e3)".to_string()),
                vec![
                    "INSUFFICIENT_LOWERCASE,2,1",
                    "INSUFFICIENT_CHARACTERISTICS,4,5",
                ],
            ),
            RulePasswordTestItem(
                create_rule2(),
                PasswordData::with_password("rscvew2e3".to_string()),
                vec!["INSUFFICIENT_SPECIAL,1,0", "INSUFFICIENT_UPPERCASE,1,0"],
            ),
        ];
        check_messages(test_cases);
    }
    fn create_rule1() -> Box<CharacterCharacteristics> {
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Alphabetical), 4).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 3).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 2).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 2).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
        ];
        Box::new(CharacterCharacteristics::with_rules_and_characteristics(char_rules, 5).unwrap())
    }
    fn create_rule2() -> Box<CharacterCharacteristics> {
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];
        Box::new(CharacterCharacteristics::new(char_rules, 3, false, true).unwrap())
    }
}

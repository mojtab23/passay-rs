use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;
use std::ops::Range;

const ERROR_CODE: &str = "INSUFFICIENT_COMPLEXITY";
const ERROR_CODE_RULES: &str = "INSUFFICIENT_COMPLEXITY_RULES";

/// Rule for determining if a password contains the desired complexity for a certain length. In order to meet the
/// criteria of this rule, passwords must meet all the supplied rules for a given password length.
/// # Example
///
/// ```
///  use passay_rs::rule::PasswordData;
///  use passay_rs::rule::illegal_sequence::IllegalSequenceRule;
///  use passay_rs::rule::sequence_data::EnglishSequenceData;
///  use passay_rs::rule::character::CharacterRule;
///  use passay_rs::rule::character_data::EnglishCharacterData;
///  use passay_rs::rule::character_characteristics::CharacterCharacteristics;
///  use passay_rs::rule::length_complexity::LengthComplexityRule;
///  use passay_rs::rule::length::LengthRule;
///  use passay_rs::rule::repeat_character::RepeatCharacterRule;
///  use passay_rs::rule::username::UsernameRule;
///  use passay_rs::rule::Rule;
///
///   let char_rules = vec![
///      CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
///  ];
///
///  let rules: Vec<Box<dyn Rule>> = vec![
///      Box::new(LengthRule::new(8, 64)),
///      Box::new(
///          CharacterCharacteristics::with_rules_and_characteristics(char_rules, 4).unwrap(),
///      ),
///      Box::new(UsernameRule::with_match_backwards_and_ignore_case(
///          true, true,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Alphabetical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Numerical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::USQwerty,
///      )),
///      Box::new(RepeatCharacterRule::default()),
///  ];
///  let mut rule = LengthComplexityRule::default();
///  let _ = rule.add_rules(0..12, rules);
///
///  let char_rules = vec![
///      CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
///  ];
///  let rules: Vec<Box<dyn Rule>> = vec![
///      Box::new(LengthRule::new(8, 64)),
///      Box::new(
///          CharacterCharacteristics::with_rules_and_characteristics(char_rules, 3).unwrap(),
///      ),
///      Box::new(UsernameRule::with_match_backwards_and_ignore_case(
///          true, true,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Alphabetical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Numerical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::USQwerty,
///      )),
///      Box::new(RepeatCharacterRule::default()),
///  ];
///  let _ = rule.add_rules(12..16, rules);
///
///  let char_rules = vec![
///      CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
///  ];
///  let rules: Vec<Box<dyn Rule>> = vec![
///      Box::new(LengthRule::new(8, 64)),
///      Box::new(
///          CharacterCharacteristics::with_rules_and_characteristics(char_rules, 2).unwrap(),
///      ),
///      Box::new(UsernameRule::with_match_backwards_and_ignore_case(
///          true, true,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Alphabetical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Numerical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::USQwerty,
///      )),
///      Box::new(RepeatCharacterRule::default()),
///  ];
///  let _ = rule.add_rules(16..20, rules);
///
///  let rules: Vec<Box<dyn Rule>> = vec![
///      Box::new(LengthRule::new(8, 64)),
///      Box::new(UsernameRule::with_match_backwards_and_ignore_case(
///          true, true,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Alphabetical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::Numerical,
///      )),
///      Box::new(IllegalSequenceRule::with_sequence_data(
///          EnglishSequenceData::USQwerty,
///      )),
///      Box::new(RepeatCharacterRule::default()),
///  ];
///  let _ = rule.add_rules(20..128, rules);
///
///  let password = PasswordData::with_password_and_user(
///      "rPscvEW2e".to_string(),
///      Some("alfred".to_string()),
///  );
///  let result = rule.validate(&password);
///  assert!(!result.valid());
/// ```
pub struct LengthComplexityRule {
    rules: HashMap<Range<usize>, Vec<Box<dyn Rule>>>,
    report_failure: bool,
    report_rule_failures: bool,
}

impl LengthComplexityRule {
    pub fn new(
        rules: HashMap<Range<usize>, Vec<Box<dyn Rule>>>,
        report_failure: bool,
        report_rule_failures: bool,
    ) -> Self {
        Self {
            rules,
            report_failure,
            report_rule_failures,
        }
    }

    pub fn rules_mut(&mut self) -> &mut HashMap<Range<usize>, Vec<Box<dyn Rule>>> {
        &mut self.rules
    }
    pub fn add_rules(
        &mut self,
        interval: Range<usize>,
        rules: Vec<Box<dyn Rule>>,
    ) -> Result<(), String> {
        if rules.is_empty() {
            return Err("Rules cannot be empty".to_string());
        }

        for existing_interval in self.rules.keys() {
            if ranges_intersect(existing_interval, &interval) {
                return Err(format!(
                    "Interval {:?} intersects existing interval {:?}",
                    interval, existing_interval
                ));
            }
        }
        let _ = &mut self.rules.insert(interval, rules);
        Ok(())
    }

    fn get_rules_by_len(&self, len: usize) -> Option<&Vec<Box<dyn Rule>>> {
        for (range, rules) in &self.rules {
            if range.contains(&len) {
                return Some(rules);
            }
        }
        None
    }
}
impl Rule for LengthComplexityRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let password_len = password_data.password.len();
        let rules_by_len = self.get_rules_by_len(password_len);
        let mut result = RuleResult::default();
        if rules_by_len.is_none() {
            result.add_error(
                ERROR_CODE_RULES,
                Some(create_rule_result_detail_parameters(password_len, 0, 0)),
            );
            return result;
        }
        let rules_by_len = rules_by_len.unwrap();
        let rules_len = rules_by_len.len();

        let mut success_count: usize = 0;
        for rule in rules_by_len {
            let mut rr = rule.validate(password_data);
            if !rr.valid() {
                if self.report_rule_failures {
                    result.details_mut().append(rr.details_mut());
                    dbg!(rr.details());
                }
            } else {
                success_count += 1;
            }
            result.metadata_mut().merge(rr.metadata());
        }
        if success_count < rules_len {
            result.set_valid(false);
            if self.report_failure {
                result.add_error(
                    ERROR_CODE,
                    Some(create_rule_result_detail_parameters(
                        password_len,
                        success_count,
                        rules_len,
                    )),
                )
            }
        }
        result
    }
}
fn create_rule_result_detail_parameters(
    len: usize,
    success: usize,
    rule_count: usize,
) -> HashMap<String, String> {
    let mut map = HashMap::with_capacity(3);
    map.insert("passwordLength".to_string(), len.to_string());
    map.insert("successCount".to_string(), success.to_string());
    map.insert("ruleCount".to_string(), rule_count.to_string());
    map
}
impl Default for LengthComplexityRule {
    fn default() -> Self {
        LengthComplexityRule {
            rules: HashMap::new(),
            report_failure: true,
            report_rule_failures: true,
        }
    }
}

fn ranges_intersect(a: &Range<usize>, b: &Range<usize>) -> bool {
    // Check if a's start is within b
    a.start >= b.start && a.start < b.end ||
        // Check if a's end is within b
        a.end > b.start && a.end <= b.end ||
        // Check if b's start is within a
        b.start >= a.start && b.start < a.end ||
        // Check if b's end is within a
        b.end > a.start && b.end <= a.end
}

#[cfg(test)]
mod tests {
    use crate::rule::character_data::CharacterData;
    use crate::rule::length::{ERROR_CODE_MAX, ERROR_CODE_MIN};
    use crate::rule::length_complexity::{ERROR_CODE, ERROR_CODE_RULES};
    use crate::rule::sequence_data::SequenceData;
    use crate::rule::{
        character::CharacterRule, character_characteristics,
        character_characteristics::CharacterCharacteristics, character_data::EnglishCharacterData,
        illegal_sequence::IllegalSequenceRule, length::LengthRule,
        length_complexity::LengthComplexityRule, repeat_character,
        repeat_character::RepeatCharacterRule, sequence_data::EnglishSequenceData, username,
        username::UsernameRule, PasswordData, Rule,
    };
    use crate::test::{check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // valid passwords in each length range
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "r%scvEW2e".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "rkscvEW2e93C".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "rkscvEWbePwCOUovqt".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "horse staple battery".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "it was the best of times".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![],
            ),
            // invalid passwords
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "r%vE2".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, ERROR_CODE_MIN],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "It was the best of times, it was the worst of times, it was the age of wisdom,".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, ERROR_CODE_MAX],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "It was the best of times, it was the worst of times, it was the age of wisdom, \
                    it was the age of foolishness, it was the epoch of belief, \
                    it was the epoch of incredulity, it was the season of Light,".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE_RULES],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "rPscvEW2e".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, character_characteristics::ERROR_CODE, EnglishCharacterData::Digit.error_code()],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "r%scvEWte".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, character_characteristics::ERROR_CODE, EnglishCharacterData::Digit.error_code()],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "r%scvew2e".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, character_characteristics::ERROR_CODE, EnglishCharacterData::UpperCase.error_code()],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "R%SCVEW2E".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, character_characteristics::ERROR_CODE, EnglishCharacterData::LowerCase.error_code()],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "rALfredTe".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, username::ERROR_CODE,character_characteristics::ERROR_CODE,
                     EnglishCharacterData::Special.error_code(), EnglishCharacterData::Digit.error_code()],
            ),
            RulePasswordTestItem(
                Box::new(rule1()),
                PasswordData::with_password_and_user(
                    "It was the best of eeeee, it was the worst of 87654".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![ERROR_CODE, repeat_character::ERROR_CODE,
                     EnglishSequenceData::USQwerty.error_code(), EnglishSequenceData::Numerical.error_code()],
            ),
            RulePasswordTestItem(
                // RULE 2
                Box::new(rule2()),
                PasswordData::with_password_and_user(
                    "It was the best of eeeee, it was the worst of 87654".to_string(),
                    Some("alfred".to_string()),
                ),
                vec![
                    ERROR_CODE,
                    EnglishSequenceData::USQwerty.error_code(),
                    EnglishSequenceData::Numerical.error_code(),
                ],
            ),
        ];
        check_passwords(test_cases);
    }

    fn rule1() -> LengthComplexityRule {
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(LengthRule::new(8, 64)),
            Box::new(
                CharacterCharacteristics::with_rules_and_characteristics(char_rules, 4).unwrap(),
            ),
            Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                true, true,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Alphabetical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Numerical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::USQwerty,
            )),
            Box::new(RepeatCharacterRule::default()),
        ];
        let mut rule = LengthComplexityRule::default();
        let _ = rule.add_rules(0..12, rules);

        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(LengthRule::new(8, 64)),
            Box::new(
                CharacterCharacteristics::with_rules_and_characteristics(char_rules, 3).unwrap(),
            ),
            Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                true, true,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Alphabetical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Numerical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::USQwerty,
            )),
            Box::new(RepeatCharacterRule::default()),
        ];
        let _ = rule.add_rules(12..16, rules);

        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(LengthRule::new(8, 64)),
            Box::new(
                CharacterCharacteristics::with_rules_and_characteristics(char_rules, 2).unwrap(),
            ),
            Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                true, true,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Alphabetical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Numerical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::USQwerty,
            )),
            Box::new(RepeatCharacterRule::default()),
        ];
        let _ = rule.add_rules(16..20, rules);

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(LengthRule::new(8, 64)),
            Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                true, true,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Alphabetical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Numerical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::USQwerty,
            )),
            Box::new(RepeatCharacterRule::default()),
        ];
        let _ = rule.add_rules(20..128, rules);
        rule
    }
    fn rule2() -> LengthComplexityRule {
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(LengthRule::new(8, 64)),
            Box::new(
                CharacterCharacteristics::with_rules_and_characteristics(char_rules, 4).unwrap(),
            ),
            Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                true, true,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Alphabetical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Numerical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::USQwerty,
            )),
            Box::new(RepeatCharacterRule::default()),
        ];
        let mut rule = LengthComplexityRule::default();
        rule.report_failure = false;
        let _ = rule.add_rules(0..20, rules);

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(LengthRule::new(8, 64)),
            Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                true, true,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Alphabetical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::Numerical,
            )),
            Box::new(IllegalSequenceRule::with_sequence_data(
                EnglishSequenceData::USQwerty,
            )),
            Box::new(RepeatCharacterRule::default()),
        ];
        let _ = rule.add_rules(20..usize::MAX, rules);
        rule
    }
}

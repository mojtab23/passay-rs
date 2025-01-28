use crate::rule::allowed_character::MatchBehavior;
use crate::rule::allowed_character::MatchBehavior::Contains;
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;
use std::ops::Range;

pub const ERROR_CODE: &str = "ILLEGAL_NUMBER_RANGE";
pub struct NumberRangeRule {
    range: Range<isize>,
    match_behavior: MatchBehavior,
    report_all: bool,
}

impl NumberRangeRule {
    pub fn new(range: Range<isize>, match_behavior: MatchBehavior, report_all: bool) -> Self {
        NumberRangeRule {
            range,
            match_behavior,
            report_all,
        }
    }
    fn create_rule_result_detail_parameters(&self, number: isize) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("number".to_string(), number.to_string());
        map.insert("matchBehavior".to_string(), self.match_behavior.to_string());
        map
    }
}

impl From<Range<isize>> for NumberRangeRule {
    fn from(value: Range<isize>) -> Self {
        NumberRangeRule::new(value, Contains, true)
    }
}

impl Rule for NumberRangeRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let text = password_data.password();
        for i in self.range.clone() {
            if self.match_behavior.match_str(text, &i.to_string()) {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters(i)),
                );
                if !self.report_all {
                    break;
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::allowed_character::MatchBehavior::{Contains, EndsWith, StartsWith};
    use crate::rule::number_range::{NumberRangeRule, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(NumberRangeRule::from(101..199)),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, StartsWith, true)),
                PasswordData::with_password("150Rcv8#n65".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, StartsWith, true)),
                PasswordData::with_password("p4zRcv101#n6F".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, EndsWith, true)),
                PasswordData::with_password("p4zRcv8#n198".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, EndsWith, true)),
                PasswordData::with_password("p4zRcv101#n6F".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::from(101..199)),
                PasswordData::with_password("p4zRcv99#n65".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::from(101..199)),
                PasswordData::with_password("p4zRcv100#n65".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::from(101..199)),
                PasswordData::with_password("p4zRcv199#n65".to_string()),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, StartsWith, true)),
                PasswordData::with_password("133Rcv8#n65".to_string()),
                vec!["ILLEGAL_NUMBER_RANGE,starts with,133"],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, Contains, true)),
                PasswordData::with_password("p4zRcv168#n65".to_string()),
                vec!["ILLEGAL_NUMBER_RANGE,contains,168"],
            ),
            RulePasswordTestItem(
                Box::new(NumberRangeRule::new(101..199, EndsWith, true)),
                PasswordData::with_password("p4zRcv8#n188".to_string()),
                vec!["ILLEGAL_NUMBER_RANGE,ends with,188"],
            ),
        ];
        check_messages(test_cases);
    }
}

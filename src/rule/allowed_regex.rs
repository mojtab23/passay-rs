use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use fancy_regex::Regex;
use std::collections::HashMap;

const ERROR_CODE: &str = "ALLOWED_MATCH";
const REGEX_ERROR: &str = "REGEX_ERROR";
pub struct AllowedRegex {
    regex: Regex,
}

impl AllowedRegex {
    pub fn from_regex(regex: Regex) -> AllowedRegex {
        AllowedRegex { regex }
    }
    fn create_rule_result_detail_parameters(&self) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("pattern".to_string(), self.regex.as_str().to_string());
        map
    }
}

impl Rule for AllowedRegex {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let result1 = self.regex.is_match(password_data.password());
        if result1.is_err() {
            result.add_error(ERROR_CODE, None)
        } else {
            if !result1.unwrap() {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters()),
                )
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::allowed_regex::{AllowedRegex, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};
    use fancy_regex::{Regex, RegexBuilder};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test invalid password
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    Regex::new("\\d\\d\\d\\d").unwrap(),
                )),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test entire password
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    Regex::new("^[\\p{Alpha}]+\\d\\d\\d\\d$").unwrap(),
                )),
                PasswordData::with_password("pwUiNh0248".to_string()),
                vec![],
            ),
            // test find password
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    Regex::new("\\d\\d\\d\\d").unwrap(),
                )),
                PasswordData::with_password("pwUiNh0248".to_string()),
                vec![],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    RegexBuilder::new("abcd").case_insensitive(true).build().unwrap(),
                )),
                PasswordData::with_password("pwUAbbCd0248xwK".to_string()),
                vec![ERROR_CODE],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(Regex::new("(?i)abcd").unwrap())),
                PasswordData::with_password("pwUAbbCd0248xwK".to_string()),
                vec![ERROR_CODE],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    RegexBuilder::new("abcd").case_insensitive(true).build().unwrap(),
                )),
                PasswordData::with_password("pwUAbCd0248xwK".to_string()),
                vec![],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(Regex::new("(?i)abcd").unwrap())),
                PasswordData::with_password("pwUAbCd0248xwK".to_string()),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    Regex::new("\\d\\d\\d\\d").unwrap(),
                )),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec!["ALLOWED_MATCH,\"\\\\d\\\\d\\\\d\\\\d\""],
            ),
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(
                    RegexBuilder::new("abcd").case_insensitive(true).build().unwrap(),
                )),
                PasswordData::with_password("p4zRabCCdv8#n65".to_string()),
                vec!["ALLOWED_MATCH,\"abcd\""],
            ),
            RulePasswordTestItem(
                Box::new(AllowedRegex::from_regex(Regex::new("(?i)abcd").unwrap())),
                PasswordData::with_password("p4zRabCCdv8#n65".to_string()),
                vec!["ALLOWED_MATCH,\"(?i)abcd\""],
            ),
        ];
        check_messages(test_cases);
    }
}

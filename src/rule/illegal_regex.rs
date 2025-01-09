use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use fancy_regex::Regex;
use std::collections::{HashMap, HashSet};

const ERROR_CODE: &str = "ILLEGAL_MATCH";
const REGEX_ERROR: &str = "REGEX_ERROR";
pub struct IllegalRegex {
    regex: Regex,
    report_all: bool,
}

impl IllegalRegex {
    pub fn new(regex: Regex, report_all: bool) -> Self {
        IllegalRegex { regex, report_all }
    }

    fn create_rule_result_detail_parameters(&self, match_str: &str) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(2);
        map.insert("match".to_string(), match_str.to_string());
        map.insert("pattern".to_string(), self.regex.as_str().to_string());
        map
    }
}

impl From<Regex> for IllegalRegex {
    fn from(regex: Regex) -> Self {
        IllegalRegex {
            regex,
            report_all: true,
        }
    }
}

impl Rule for IllegalRegex {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let mut matches = HashSet::new();
        for mat in self.regex.find_iter(&password_data.password) {
            if mat.is_err() {
                result.add_error(REGEX_ERROR, None);
                continue;
            }
            let match_str = mat.unwrap().as_str().to_string();
            if !matches.contains(&match_str) {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters(&match_str)),
                );
                if !self.report_all {
                    break;
                }
                matches.insert(match_str);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::illegal_regex::{IllegalRegex, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};
    use fancy_regex::{Regex, RegexBuilder};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test entire password
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(
                    Regex::new("^[\\p{Alpha}]+\\d\\d\\d\\d$").unwrap(),
                )),
                PasswordData::with_password("pwUiNh0248".to_string()),
                vec![ERROR_CODE],
            ),
            // test find password
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("pwUi0248xwK".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("pwUi0248xwK9753".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test single match
            RulePasswordTestItem(
                Box::new(IllegalRegex::new(
                    Regex::new("\\d\\d\\d\\d").unwrap(),
                    false,
                )),
                PasswordData::with_password("pwUi0248xwK9753".to_string()),
                vec![ERROR_CODE],
            ),
            // test duplicate matches
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("pwUi0248xwK9753uu0248".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(
                    RegexBuilder::new("abcd").case_insensitive(true).build().unwrap(),
                )),
                PasswordData::with_password("p4zRaBcDv8#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(
                    RegexBuilder::new("abcd").case_insensitive(true).build().unwrap(),
                )),
                PasswordData::with_password("p4zRaBBcDv8#n65".to_string()),
                vec![],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("(?i)abcd").unwrap())),
                PasswordData::with_password("p4zRaBcDv8#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test case-insensitive
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("(?i)abcd").unwrap())),
                PasswordData::with_password("p4zRaBBcDv8#n65".to_string()),
                vec![],
            ),
        ];

        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("pwUiNh0248".to_string()),
                vec!["ILLEGAL_MATCH,0248"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("pwUiNh0248xwK9753".to_string()),
                vec!["ILLEGAL_MATCH,0248", "ILLEGAL_MATCH,9753"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalRegex::new(
                    Regex::new("\\d\\d\\d\\d").unwrap(),
                    false,
                )),
                PasswordData::with_password("pwUiNh0248xwK9753".to_string()),
                vec!["ILLEGAL_MATCH,0248"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("\\d\\d\\d\\d").unwrap())),
                PasswordData::with_password("pwUiNh0248xwK9753uu0248".to_string()),
                vec!["ILLEGAL_MATCH,0248", "ILLEGAL_MATCH,9753"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(
                    RegexBuilder::new("abcd").case_insensitive(true).build().unwrap(),
                )),
                PasswordData::with_password("pwABCD0248".to_string()),
                vec!["ILLEGAL_MATCH,ABCD"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalRegex::from(Regex::new("(?i)abcd").unwrap())),
                PasswordData::with_password("pwABCD0248".to_string()),
                vec!["ILLEGAL_MATCH,ABCD"],
            ),
        ];
        check_messages(test_cases);
    }
}

use crate::rule::allowed_character::MatchBehavior;
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;

pub(crate) const ERROR_CODE: &str = "ILLEGAL_USERNAME";
pub(crate) const ERROR_CODE_REVERSED: &str = "ILLEGAL_USERNAME_REVERSED";

/// Rule for determining if a password contains the username associated with that password.
/// This rule returns true if a supplied [PasswordData] returns a None or empty username.
///
/// # Example
///
/// ```
///  use passay_rs::rule::username::UsernameRule;
///  use passay_rs::rule::PasswordData;
///  use passay_rs::rule::Rule;
///
///  let rule = UsernameRule::with_match_backwards_and_ignore_case( true, false);
///
///  let password = PasswordData::with_password_and_user(
///      "p4resutset#n65".to_string(),
///      Some("testuser".to_string()),
///  );
///  let result = rule.validate(&password);
///  assert!(!result.valid());
/// ```
pub struct UsernameRule {
    match_backwards: bool,
    ignore_case: bool,
    match_behavior: MatchBehavior,
}

impl UsernameRule {
    pub fn new(match_backwards: bool, ignore_case: bool, match_behavior: MatchBehavior) -> Self {
        Self {
            match_backwards,
            ignore_case,
            match_behavior,
        }
    }
    pub fn with_match_backwards_and_ignore_case(match_backwards: bool, ignore_case: bool) -> Self {
        Self {
            match_backwards,
            ignore_case,
            match_behavior: MatchBehavior::Contains,
        }
    }

    pub fn with_match_behavior(match_behavior: MatchBehavior) -> Self {
        Self {
            match_backwards: false,
            ignore_case: false,
            match_behavior,
        }
    }
    fn create_rule_result_detail_parameters(&self, username: &str) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(2);
        map.insert("username".to_string(), username.to_string());
        map.insert("matchBehavior".to_string(), self.match_behavior.to_string());
        map
    }
}

impl Rule for UsernameRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();

        if let Some(user) = password_data.username() {
            if user.is_empty() {
                return result;
            }
            let text = if self.ignore_case {
                password_data.password().to_lowercase()
            } else {
                password_data.password().to_string()
            };
            let user = if self.ignore_case {
                user.to_lowercase()
            } else {
                user.to_string()
            };

            if self.match_behavior.match_str(&text, &user) {
                result.add_error(
                    ERROR_CODE,
                    Some(self.create_rule_result_detail_parameters(&user)),
                );
            }

            if self.match_backwards {
                let reverse_user = user.chars().rev().collect::<String>();
                if self.match_behavior.match_str(&text, reverse_user.as_str()) {
                    result.add_error(
                        ERROR_CODE_REVERSED,
                        Some(self.create_rule_result_detail_parameters(&user)),
                    );
                }
            }
            result
        } else {
            result
        }
    }
}

impl Default for UsernameRule {
    fn default() -> Self {
        Self {
            match_backwards: false,
            ignore_case: false,
            match_behavior: MatchBehavior::Contains,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::PasswordData;
    use crate::rule::allowed_character::MatchBehavior;
    use crate::rule::username::{ERROR_CODE, ERROR_CODE_REVERSED, UsernameRule};
    use crate::test::{RulePasswordTestItem, check_messages, check_passwords};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password("p4t3stu$er#n65".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4t3stu$er#n65".to_string(),
                    Some("".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4t3stu$er#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            // match username
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4TestUser#n65".to_string(),
                    Some("TestUser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            // negative testing for backwards and case sensitive
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4resutset#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4TEStuSER#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("TestUser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4RESUTsET#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            // backwards matching
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, false,
                )),
                PasswordData::with_password_and_user(
                    "p4t3stu$er#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, false,
                )),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, false,
                )),
                PasswordData::with_password_and_user(
                    "p4resutset#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE_REVERSED],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, false,
                )),
                PasswordData::with_password_and_user(
                    "p4TEStuSER#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, false,
                )),
                PasswordData::with_password_and_user(
                    "p4RESUTsET#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            // case insensitive matching
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    false, true,
                )),
                PasswordData::with_password_and_user(
                    "p4t3stu$er#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    false, true,
                )),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    false, true,
                )),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("TestUser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    false, true,
                )),
                PasswordData::with_password_and_user(
                    "p4resutset#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    false, true,
                )),
                PasswordData::with_password_and_user(
                    "p4TEStuSER#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    false, true,
                )),
                PasswordData::with_password_and_user(
                    "p4RESUTsET#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            // both backwards and case-insensitive matching
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4t3stu$er#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("TestUser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4resutset#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE_REVERSED],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4resutset#n65".to_string(),
                    Some("TestUser".to_string()),
                ),
                vec![ERROR_CODE_REVERSED],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4TEStuSER#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, true,
                )),
                PasswordData::with_password_and_user(
                    "p4RESUTsET#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE_REVERSED],
            ),
            // test match behavior
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_behavior(MatchBehavior::StartsWith)),
                PasswordData::with_password_and_user(
                    "testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_behavior(MatchBehavior::StartsWith)),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_behavior(MatchBehavior::EndsWith)),
                PasswordData::with_password_and_user(
                    "p4#n65testuser".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_behavior(MatchBehavior::EndsWith)),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let username = "testuser";
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(UsernameRule::default()),
                PasswordData::with_password_and_user(
                    "p4testuser#n65".to_string(),
                    Some(username.to_string()),
                ),
                vec!["ILLEGAL_USERNAME,contains,testuser"],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_backwards_and_ignore_case(
                    true, false,
                )),
                PasswordData::with_password_and_user(
                    "p4resutset#n65".to_string(),
                    Some(username.to_string()),
                ),
                vec!["ILLEGAL_USERNAME_REVERSED,contains,testuser"],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_behavior(MatchBehavior::StartsWith)),
                PasswordData::with_password_and_user(
                    "testuser#n65".to_string(),
                    Some(username.to_string()),
                ),
                vec!["ILLEGAL_USERNAME,starts with,testuser"],
            ),
            RulePasswordTestItem(
                Box::new(UsernameRule::with_match_behavior(MatchBehavior::EndsWith)),
                PasswordData::with_password_and_user(
                    "p4#n65testuser".to_string(),
                    Some(username.to_string()),
                ),
                vec!["ILLEGAL_USERNAME,ends with,testuser"],
            ),
        ];
        check_messages(test_cases);
    }
}

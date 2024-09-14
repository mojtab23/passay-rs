use crate::rule::reference::{Reference, Salt};
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

const ERROR_CODE: &str = "HISTORY_VIOLATION";

#[derive(Clone)]
pub struct HistoryRule {
    report_all: bool,
}

impl HistoryRule {
    pub fn new(report_all: bool) -> HistoryRule {
        HistoryRule { report_all }
    }

    fn create_rule_result_detail_parameters(len: usize) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("historySize".to_string(), len.to_string());
        map
    }
}

impl Rule for HistoryRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let history_refs = password_data.password_references().iter().filter(|rf| {
            let option = (**rf).as_any().downcast_ref::<HistoricalReference>();
            option.is_some()
        });
        let len = history_refs.clone().count();
        if len == 0 {
            return result;
        }
        let cleartext = password_data.password();
        if self.report_all {
            history_refs
                .filter(|rf| matches(cleartext, rf))
                .for_each(|rf| {
                    result.add_error(
                        ERROR_CODE,
                        Some(Self::create_rule_result_detail_parameters(len)),
                    );
                });
        } else {
            let x = history_refs.filter(|rf| matches(cleartext, rf)).next();
            if x.is_some() {
                result.add_error(
                    ERROR_CODE,
                    Some(Self::create_rule_result_detail_parameters(len)),
                );
            }
        };
        result
    }
}

impl Default for HistoryRule {
    fn default() -> Self {
        Self { report_all: true }
    }
}
fn matches(password: &str, rf: &Box<dyn Reference>) -> bool {
    password == rf.password()
}

pub struct HistoricalReference {
    label: Option<String>,
    password: String,
    salt: Option<Box<dyn Salt>>,
}

impl HistoricalReference {
    pub fn new(
        password: String,
        label: Option<String>,
        salt: Option<Box<dyn Salt>>,
    ) -> HistoricalReference {
        HistoricalReference {
            password,
            label,
            salt,
        }
    }

    pub fn with_password(password: String) -> HistoricalReference {
        Self::with_password_and_label(password, None)
    }
    pub fn with_password_and_label(password: String, label: Option<String>) -> HistoricalReference {
        Self::new(password, label, None)
    }
}

impl Debug for HistoricalReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoricalReference")
            .field("password", &self.password)
            .field("label", &self.label)
            .finish()
    }
}

impl Reference for HistoricalReference {
    fn password(&self) -> &str {
        self.password.as_str()
    }

    fn salt(&self) -> &Option<Box<dyn Salt>> {
        &self.salt
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::rule::history::{HistoricalReference, HistoryRule, ERROR_CODE};
    use crate::rule::reference::Reference;
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let rule = HistoryRule::default();
        let rule_report_first = HistoryRule::new(false);
        let empty_rule = HistoryRule::default();
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(empty_rule.clone()),
                PasswordData::with_password_and_user(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(empty_rule.clone()),
                PasswordData::with_password_and_user(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(empty_rule.clone()),
                PasswordData::with_password_and_user(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(empty_rule.clone()),
                PasswordData::with_password_and_user(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let rule = HistoryRule::default();
        let rule_report_first = HistoryRule::new(false);

        let history_len = setup_history().len();
        let message = "HISTORY_VIOLATION,".to_owned() + history_len.to_string().as_str();

        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![&message],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![&message, &message],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    setup_history(),
                ),
                vec![&message],
            ),
        ];
        check_messages(test_cases);
    }

    fn setup_history() -> Vec<Box<dyn Reference>> {
        vec![
            Box::new(HistoricalReference::with_password_and_label(
                "t3stUs3r01".to_string(),
                Some("history".to_string()),
            )),
            Box::new(HistoricalReference::with_password_and_label(
                "t3stUs3r02".to_string(),
                Some("history".to_string()),
            )),
            Box::new(HistoricalReference::with_password_and_label(
                "t3stUs3r03".to_string(),
                Some("history".to_string()),
            )),
            Box::new(HistoricalReference::with_password_and_label(
                "t3stUs3r02".to_string(),
                Some("history".to_string()),
            )),
        ]
    }
}

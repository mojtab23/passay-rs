use crate::rule::reference::{Reference, Salt};
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

pub(super) const ERROR_CODE: &str = "SOURCE_VIOLATION";
#[derive(Clone)]
pub struct SourceRule {
    report_all: bool,
}

impl SourceRule {
    pub fn new(report_all: bool) -> SourceRule {
        SourceRule { report_all }
    }
}

impl Default for SourceRule {
    fn default() -> Self {
        SourceRule::new(true)
    }
}

impl Rule for SourceRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        validate_with_source_references(self.report_all, password_data, matches)
    }
}

pub(super) fn validate_with_source_references<F: Fn(&str, &SourceReference) -> bool>(
    report_all: bool,
    password_data: &PasswordData,
    matcher: F,
) -> RuleResult {
    let mut result = RuleResult::default();

    let source_refs = password_data
        .password_references()
        .iter()
        .filter_map(|rf| rf.as_any().downcast_ref::<SourceReference>());

    let len = source_refs.clone().count();

    if len < 1 {
        return result;
    }
    let cleartext = password_data.password();
    if report_all {
        source_refs.filter(|&rf| matcher(cleartext, rf)).for_each(|rf| {
            result.add_error(
                ERROR_CODE,
                Some(create_rule_result_detail_parameters(rf.label())),
            );
        });
    } else {
        let rf = source_refs.filter(|&rf| matcher(cleartext, rf)).next();
        if rf.is_some() {
            result.add_error(
                ERROR_CODE,
                Some(create_rule_result_detail_parameters(rf.unwrap().label())),
            );
        }
    };
    result
}
fn create_rule_result_detail_parameters(source: &str) -> HashMap<String, String> {
    let mut map = HashMap::with_capacity(1);
    map.insert("source".to_string(), source.to_string());
    map
}
fn matches(password: &str, rf: &SourceReference) -> bool {
    password == rf.password()
}
pub struct SourceReference {
    label: String,
    password: String,
    salt: Option<Salt>,
}

impl SourceReference {
    pub fn new(label: String, password: String, salt: Salt) -> Self {
        SourceReference {
            label,
            password,
            salt: Some(salt),
        }
    }
    pub fn with_label_and_password(label: String, password: String) -> Self {
        SourceReference {
            label,
            password,
            salt: None,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Debug for SourceReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceReference")
            .field("password", &self.password)
            .field("label", &self.label)
            .finish()
    }
}

impl Reference for SourceReference {
    fn password(&self) -> &str {
        &self.password
    }

    fn salt(&self) -> &Option<Salt> {
        &self.salt
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::rule::reference::Reference;
    use crate::rule::source::{SourceReference, SourceRule, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let rule = SourceRule::default();
        let rule_report_first = SourceRule::new(false);
        let empty_rule = SourceRule::default();
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r04".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r05".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r04".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first.clone()),
                PasswordData::new(
                    "t3stUs3r05".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![ERROR_CODE],
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
                    "t3stUs3r04".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(empty_rule.clone()),
                PasswordData::with_password_and_user(
                    "t3stUs3r05".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }
    #[test]
    fn test_messages() {
        let rule = SourceRule::default();
        let rule_report_first = SourceRule::new(false);

        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r04".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec!["SOURCE_VIOLATION,System A"],
            ),
            RulePasswordTestItem(
                Box::new(rule.clone()),
                PasswordData::new(
                    "t3stUs3r05".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec!["SOURCE_VIOLATION,System A", "SOURCE_VIOLATION,System A"],
            ),
            RulePasswordTestItem(
                Box::new(rule_report_first),
                PasswordData::new(
                    "t3stUs3r05".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec!["SOURCE_VIOLATION,System A"],
            ),
        ];
        check_messages(test_cases);
    }

    fn create_sources() -> Vec<Box<dyn Reference>> {
        vec![
            Box::new(SourceReference::with_label_and_password(
                "System A".to_string(),
                "t3stUs3r04".to_string(),
            )),
            Box::new(SourceReference::with_label_and_password(
                "System A".to_string(),
                "t3stUs3r05".to_string(),
            )),
            Box::new(SourceReference::with_label_and_password(
                "System A".to_string(),
                "t3stUs3r05".to_string(),
            )),
        ]
    }
}

use crate::rule::message_resolver::{DebugMessageResolver, MessageResolver};
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};

pub(crate) struct RulePasswordTestItem<'a>(pub Box<dyn Rule>, pub PasswordData, pub Vec<&'a str>);
pub(crate) fn check_passwords(items: Vec<RulePasswordTestItem>) {
    for (case_num, item) in items.iter().enumerate() {
        let rule = &item.0;
        let password = &item.1;
        let expected_errors = &item.2;

        let result = rule.validate(password);
        if !expected_errors.is_empty() {
            dbg!(case_num, password, &expected_errors);
            if !result.valid() {
                assert!(!result.valid());
            }
            assert_eq!(
                expected_errors.len(),
                result.details().len(),
                "[CASE:{}] expected {} errors but got {}",
                case_num,
                expected_errors.len(),
                result.details().len()
            );
            for error_code in expected_errors {
                has_error_code(error_code, &result);
            }
        } else {
            dbg!(case_num, password, "valid password");
            assert!(result.valid());
        }
    }
}

pub(crate) fn check_messages(items: Vec<RulePasswordTestItem>) {
    for item in items {
        let resolver = DebugMessageResolver;
        let rule = item.0;
        let password = &item.1;
        let expected_errors = item.2;
        let result = rule.validate(password);
        assert!(!result.valid(), "rule result should be invalid");
        assert_eq!(expected_errors.len(), result.details().len());

        for i in 0..result.details().len() {
            let result_detail = result.details().get(i).unwrap();
            let error = expected_errors[i];
            let resolved_message = resolver.resolve(result_detail);
            for part in error.split(",") {
                if part.is_empty() {
                    panic!("empty error part is not allowed")
                }
                assert!(
                    resolved_message.contains(part),
                    "expected {part:?} not found in resolved message: {resolved_message:?}"
                );
            }
        }
    }
}

fn has_error_code(code: &str, result: &RuleResult) -> bool {
    for detail in result.details() {
        if code == detail.error_code() {
            return true;
        }
    }
    false
}

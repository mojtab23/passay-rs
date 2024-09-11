use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};

pub struct PasswordValidator {
    password_rules: Vec<Box<dyn Rule>>,
}

impl PasswordValidator {
    pub fn new(password_rules: Vec<Box<dyn Rule>>) -> Self {
        Self { password_rules }
    }

    pub fn rules(&self) -> &Vec<Box<dyn Rule>> {
        &self.password_rules
    }
}

impl Rule for PasswordValidator {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let vec = &self.password_rules;
        let mut result = RuleResult::new(true);
        for rule in vec {
            let mut rr = rule.validate(password_data);
            result.metadata_mut().merge(rr.metadata());
            if !rr.valid() {
                result.set_valid(false);
                result.details_mut().append(rr.details_mut());
            };
        }
        result
    }
}

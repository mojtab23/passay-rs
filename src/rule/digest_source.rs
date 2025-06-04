use crate::hash::Hasher;
use crate::rule::reference::Reference;
use crate::rule::rule_result::RuleResult;
use crate::rule::source::{validate_with_source_references, SourceReference};
use crate::rule::{PasswordData, Rule};

pub struct DigestSourceRule<H>
where
    H: Hasher<String>,
{
    hasher: H,
    report_all: bool,
}

impl<H> DigestSourceRule<H>
where
    H: Hasher<String>,
{
    pub fn new(hasher: H, report_all: bool) -> Self {
        Self { hasher, report_all }
    }
}

impl<H> Rule for DigestSourceRule<H>
where
    H: Hasher<String>,
{
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let matcher = |password: &str, rf: &SourceReference| {
            let pass = password.to_string();
            let undigested = match rf.salt() {
                None => pass,
                Some(salt) => salt.apply_to(pass),
            };
            let h = &self.hasher;
            h.compare(rf.password().as_bytes(), undigested.as_bytes()).unwrap_or(false)
        };
        validate_with_source_references(self.report_all, password_data, matcher)
    }
}

#[cfg(test)]
mod test {
    use crate::rule::digest_history::test::Sha1Hasher;
    use crate::rule::digest_source::DigestSourceRule;
    use crate::rule::reference::Reference;
    use crate::rule::source::{SourceReference, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r04".to_string(),
                    Some("testuser".to_string()),
                    create_sources(),
                ),
                vec![ERROR_CODE],
            ),
            // without source reference
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::with_password_and_user(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            // without source reference
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::with_password_and_user(
                    "t3stUs3r04".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }
    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![RulePasswordTestItem(
            Box::new(create_digest_rule()),
            PasswordData::new(
                "t3stUs3r04".to_string(),
                Some("testuser".to_string()),
                create_sources(),
            ),
            vec!["SOURCE_VIOLATION,System B"],
        )];
        check_messages(test_cases);
    }
    fn create_sources() -> Vec<Box<dyn Reference>> {
        vec![Box::new(SourceReference::with_password_label(
            "CJGTDMQRP+rmHApkcijC80aDV0o=".to_string(),
            "System B".to_string(),
        ))]
    }
    fn create_digest_rule() -> DigestSourceRule<Sha1Hasher> {
        DigestSourceRule::new(Sha1Hasher, true)
    }
}

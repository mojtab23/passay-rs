use crate::hash::Hasher;
use crate::rule::reference::Reference;
use crate::rule::rule_result::RuleResult;
use crate::rule::source::{SourceReference, validate_with_source_references};
use crate::rule::{PasswordData, Rule};

/// Rule for determining if a password matches a digested password from a different source. Useful for when separate
/// systems cannot have matching passwords. If no password reference has been set that matches the label on the rule,
/// then passwords will meet this rule. See also [PasswordData::password_references]
///
/// # Example
///
/// ```
///#  use base64::Engine;
///#  use passay_rs::hash::Hasher;
///#  struct Sha1Hasher;
///#  impl Hasher<String> for Sha1Hasher {
///#      fn hash(&self, data: &[u8]) -> Result<Vec<u8>, String> {
///#          todo!()
///#      }
///#
///#      fn compare(&self, hash: &[u8], data: &[u8]) -> Result<bool, String> {
///#          let hash_bytes = base64::prelude::BASE64_STANDARD.decode(hash).unwrap();
///#          let data_sha1 = sha1_smol::Sha1::from(data).digest().bytes();
///#          Ok(hash_bytes.eq(&data_sha1))
///#      }
///#  }
///  use passay_rs::rule::digest_source::DigestSourceRule;
///  use passay_rs::rule::source::SourceReference;
///  use passay_rs::rule::reference::Reference;
///  use passay_rs::rule::PasswordData;
///  use passay_rs::rule::Rule;
///
///  let rule = DigestSourceRule::new(Sha1Hasher, true);
///  let source: Vec<Box<dyn Reference>> = vec![Box::new(SourceReference::with_password_label(
///      "CJGTDMQRP+rmHApkcijC80aDV0o=".to_string(),
///      "System B".to_string(),
///  ))];
///  let password = PasswordData::new(
///      "t3stUs3r04".to_string(),
///      Some("testuser".to_string()),
///      source,
///  );
///  let result = rule.validate(&password);
///  assert!(!result.valid());
/// ```
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
    use crate::rule::PasswordData;
    use crate::rule::digest_history::test::Sha1Hasher;
    use crate::rule::digest_source::DigestSourceRule;
    use crate::rule::reference::Reference;
    use crate::rule::source::{ERROR_CODE, SourceReference};
    use crate::test::{RulePasswordTestItem, check_messages, check_passwords};

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

use crate::hash::Hasher;
use crate::rule::history::{validate_with_history_references, HistoricalReference};
use crate::rule::reference::Reference;
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};

pub struct DigestHistoryRule<H>
where
    H: Hasher<String>,
{
    hasher: H,
    report_all: bool,
}

impl<H> DigestHistoryRule<H>
where
    H: Hasher<String>,
{
    pub fn new(hasher: H, report_all: bool) -> Self {
        Self { hasher, report_all }
    }
}

impl<H> Rule for DigestHistoryRule<H>
where
    H: Hasher<String>,
{
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let matcher = |password: &str, rf: &HistoricalReference| {
            let pass = password.to_string();
            let undigested = match rf.salt() {
                None => pass,
                Some(salt) => salt.apply_to(pass),
            };
            let h = &self.hasher;
            h.compare(rf.password().as_bytes(), undigested.as_bytes()).unwrap_or(false)
        };

        validate_with_history_references(self.report_all, password_data, matcher)
    }
}

#[cfg(test)]
mod test {
    use crate::hash::Hasher;
    use crate::rule::digest_history::DigestHistoryRule;
    use crate::rule::history::{HistoricalReference, ERROR_CODE};
    use crate::rule::reference::Reference;
    use crate::rule::reference::Salt::{Prefix, Suffix};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};
    use base64::Engine;

    #[test]
    fn test_passwords() {
        let bcrypt_ref = Box::new(HistoricalReference::with_label_password(
            "$2a$5$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe".to_string(),
            "bcrypt-history".to_string(),
        ));
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                    create_digest_refs(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    create_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    create_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                    create_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            // // salted digest rules TODO strange logic
            // RulePasswordTestItem(
            //     Box::new(create_digest_rule()),
            //     PasswordData::new(
            //         "t3stUs3r00".to_string(),
            //         Some("testuser".to_string()),
            //         create_salted_digest_refs(),
            //     ),
            //     vec![],
            // ),
            // RulePasswordTestItem(
            //     Box::new(create_digest_rule()),
            //     PasswordData::new(
            //         "t3stUs3r01".to_string(),
            //         Some("testuser".to_string()),
            //         create_salted_digest_refs(),
            //     ),
            //     vec![ERROR_CODE],
            // ),
            // RulePasswordTestItem(
            //     Box::new(create_digest_rule()),
            //     PasswordData::new(
            //         "t3stUs3r02".to_string(),
            //         Some("testuser".to_string()),
            //         create_salted_digest_refs(),
            //     ),
            //     vec![ERROR_CODE],
            // ),
            // RulePasswordTestItem(
            //     Box::new(create_digest_rule()),
            //     PasswordData::new(
            //         "t3stUs3r03".to_string(),
            //         Some("testuser".to_string()),
            //         create_salted_digest_refs(),
            //     ),
            //     vec![ERROR_CODE],
            // ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                    create_prefix_salted_digest_refs(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    create_prefix_salted_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    create_prefix_salted_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                    create_prefix_salted_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                    create_suffix_salted_digest_refs(),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                    create_suffix_salted_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                    create_suffix_salted_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::new(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                    create_suffix_salted_digest_refs(),
                ),
                vec![ERROR_CODE],
            ),
            // empty history
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::with_password_and_user(
                    "t3stUs3r00".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::with_password_and_user(
                    "t3stUs3r01".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::with_password_and_user(
                    "t3stUs3r02".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(create_digest_rule()),
                PasswordData::with_password_and_user(
                    "t3stUs3r03".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(DigestHistoryRule::new(BcryptHasher, true)),
                PasswordData::with_password_and_user(
                    "p@$$w0rd".to_string(),
                    Some("testuser".to_string()),
                ),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(DigestHistoryRule::new(BcryptHasher, true)),
                PasswordData::new(
                    "password".to_string(),
                    Some("testuser".to_string()),
                    vec![bcrypt_ref],
                ),
                vec![ERROR_CODE],
            ),
        ];
        check_passwords(test_cases);
    }
    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![RulePasswordTestItem(
            Box::new(create_digest_rule()),
            PasswordData::new(
                "t3stUs3r01".to_string(),
                Some("testuser".to_string()),
                create_digest_refs(),
            ),
            vec!["HISTORY_VIOLATION,3"],
        )];
        check_messages(test_cases);
    }
    fn create_digest_refs() -> Vec<Box<dyn Reference>> {
        vec![
            Box::new(HistoricalReference::with_label_password(
                "safx/LW8+SsSy/o3PmCNy4VEm5s=".to_string(),
                "history".to_string(),
            )),
            Box::new(HistoricalReference::with_label_password(
                "zurb9DyQ5nooY1la8h86Bh0n1iw=".to_string(),
                "history".to_string(),
            )),
            Box::new(HistoricalReference::with_label_password(
                "bhqabXwE3S8E6xNJfX/d76MFOCs=".to_string(),
                "history".to_string(),
            )),
        ]
    }
    fn create_prefix_salted_digest_refs() -> Vec<Box<dyn Reference>> {
        vec![
            Box::new(HistoricalReference::new(
                "lHGQFf9tTVUOCG3CoNqdKaiCThA=".to_string(),
                Some("pre-salt-history".to_string()),
                Some(Prefix("xyz".to_string())),
            )),
            Box::new(HistoricalReference::new(
                "GtEfsfrBomR/3aD5RfBGWPOKlYc=".to_string(),
                Some("pre-salt-history".to_string()),
                Some(Prefix("xyz".to_string())),
            )),
            Box::new(HistoricalReference::new(
                "XZ2CO63FrS5N7wvCmyzkiBAYNoY=".to_string(),
                Some("pre-salt-history".to_string()),
                Some(Prefix("xyz".to_string())),
            )),
        ]
    }
    fn create_suffix_salted_digest_refs() -> Vec<Box<dyn Reference>> {
        vec![
            Box::new(HistoricalReference::new(
                "HnBhNzaSRdKqmIZbau97E++rysM=".to_string(),
                Some("suf-salt-history".to_string()),
                Some(Suffix("xyz".to_string())),
            )),
            Box::new(HistoricalReference::new(
                "ScDf3gIY16LF6UAeWVr7nZHSvbE=".to_string(),
                Some("suf-salt-history".to_string()),
                Some(Suffix("xyz".to_string())),
            )),
            Box::new(HistoricalReference::new(
                "apjCHJyez2IvOlBM5mqD2DvSk6o=".to_string(),
                Some("suf-salt-history".to_string()),
                Some(Suffix("xyz".to_string())),
            )),
        ]
    }
    // fn create_salted_digest_refs() -> Vec<Box<dyn Reference>> {
    //     vec![
    //         Box::new(HistoricalReference::with_label_password(
    //             "2DSZvOzGiMnm/Mbxt1M3zNAh7P1GebLG".to_string(),
    //             "salted-history".to_string(),
    //         )),
    //         Box::new(HistoricalReference::with_label_password(
    //             "rv1mF2DuarrF//LPP9+AFJal8bMc9G5z".to_string(),
    //             "salted-history".to_string(),
    //         )),
    //         Box::new(HistoricalReference::with_label_password(
    //             "3lABdWxtWhfGKtXBx4MfiWZ1737KnFuG".to_string(),
    //             "salted-history".to_string(),
    //         )),
    //     ]
    // }
    fn create_digest_rule() -> DigestHistoryRule<Sha1Hasher> {
        DigestHistoryRule::new(Sha1Hasher, true)
    }
    struct Sha1Hasher;
    impl Hasher<String> for Sha1Hasher {
        fn hash(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            todo!()
        }

        fn compare(&self, hash: &[u8], data: &[u8]) -> Result<bool, String> {
            let hash_bytes = base64::prelude::BASE64_STANDARD.decode(hash).unwrap();
            dbg!(&hash_bytes);
            let data_sha1 = sha1_smol::Sha1::from(data).digest().bytes();
            dbg!(&data_sha1);
            Ok(hash_bytes.eq(&data_sha1))
        }
    }
    struct BcryptHasher;
    impl Hasher<String> for BcryptHasher {
        fn hash(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            todo!()
        }

        fn compare(&self, hash: &[u8], data: &[u8]) -> Result<bool, String> {
            let hash = String::from_utf8_lossy(hash);
            bcrypt::verify(data, &hash).map_err(|err| err.to_string())
        }
    }
}

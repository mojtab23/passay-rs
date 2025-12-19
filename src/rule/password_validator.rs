use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use std::ops::Deref;
use std::rc::Rc;

/// The central component for evaluating multiple password rules against a candidate password.
/// # Example
///
/// ```
///  use passay_rs::rule::character_data::EnglishCharacterData;
///  use passay_rs::rule::length::LengthRule;
///  use passay_rs::rule::character::CharacterRule;
///  use passay_rs::rule::character_characteristics::CharacterCharacteristics;
///  use passay_rs::rule::illegal_sequence::IllegalSequenceRule;
///  use passay_rs::rule::sequence_data::EnglishSequenceData;
///  use passay_rs::rule::repeat_character::RepeatCharacterRule;
///  use passay_rs::rule::Rule;
///  use passay_rs::rule::password_validator::PasswordValidator;
///  use passay_rs::rule::PasswordData;
///
///  let length_rule = LengthRule::new(8, 16);
///  let char_rules = vec![
///      CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
///      CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
///  ];
///  let char_rule =
///      CharacterCharacteristics::with_rules_and_characteristics(char_rules, 3).unwrap();
///  let qwerty_seq_rule =
///      IllegalSequenceRule::with_sequence_data(EnglishSequenceData::USQwerty);
///  let alpha_seq_rule =
///      IllegalSequenceRule::with_sequence_data(EnglishSequenceData::Alphabetical);
///  let num_seq_rule = IllegalSequenceRule::with_sequence_data(EnglishSequenceData::Numerical);
///  let dup_seq_rule = RepeatCharacterRule::default();
///
///  let rules: Vec<Box<dyn Rule>> = vec![
///      Box::new(char_rule),
///      Box::new(length_rule),
///      Box::new(qwerty_seq_rule),
///      Box::new(alpha_seq_rule),
///      Box::new(num_seq_rule),
///      Box::new(dup_seq_rule),
///  ];
///  let password_validator = PasswordValidator::new(rules);
///
///  let invalid_pass = "aBcDeFgHiJk".to_string();
///  let pass_data = PasswordData::with_password(invalid_pass);
///  let rule_result = password_validator.validate(&pass_data);
///  assert!(!rule_result.valid());
///  assert!(!rule_result.details().is_empty());
/// ```
#[derive(Clone)]
pub struct PasswordValidator {
    password_rules: Rc<Vec<Box<dyn Rule>>>,
}

impl PasswordValidator {
    pub fn new(password_rules: Vec<Box<dyn Rule>>) -> Self {
        let password_rules = Rc::new(password_rules);
        Self { password_rules }
    }

    pub fn rules(&self) -> &Vec<Box<dyn Rule>> {
        &self.password_rules
    }
}

impl Rule for PasswordValidator {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let vec = self.password_rules.deref();
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

#[cfg(test)]
mod tests {
    use crate::dictionary::Dictionary;
    use crate::dictionary::word_lists::create_from_read;
    use crate::dictionary::word_lists::sort::SliceSort;
    use crate::dictionary::word_lists::word_list_dictionary::WordListDictionary;
    use crate::rule::character::CharacterRule;
    use crate::rule::character_characteristics::{CharacterCharacteristics, ERROR_CODE};
    use crate::rule::character_data::{CharacterData, EnglishCharacterData};
    use crate::rule::dictionary_substring::DictionarySubstringRule;
    use crate::rule::digest_history::DigestHistoryRule;
    use crate::rule::digest_history::test::Sha1Hasher;
    use crate::rule::digest_source::DigestSourceRule;
    use crate::rule::history::HistoricalReference;
    use crate::rule::illegal_sequence::IllegalSequenceRule;
    use crate::rule::length::LengthRule;
    use crate::rule::password_validator::PasswordValidator;
    use crate::rule::reference::Reference;
    use crate::rule::repeat_character::RepeatCharacterRule;
    use crate::rule::sequence_data::{EnglishSequenceData, SequenceData};
    use crate::rule::source::SourceReference;
    use crate::rule::username::UsernameRule;
    use crate::rule::whitespace::WhitespaceRule;
    use crate::rule::{
        PasswordData, Rule, dictionary, dictionary_substring, history, length, source, username,
        whitespace,
    };
    use crate::test::{RulePasswordTestItem, check_messages, check_passwords};

    // The test producerExtends in java code is not needed here
    const USER: &str = "testuser";

    #[test]
    fn validate() {
        const VALID_PASS: &str = "aBcD3FgH1Jk";
        let pv = PasswordValidator::new(create_validate_rules());
        let pass_data = PasswordData::with_password(VALID_PASS.to_string());
        let rule_result = pv.validate(&pass_data);
        assert!(rule_result.valid());
        assert!(rule_result.details().is_empty());

        const INVALID_PASS: &str = "aBcDeFgHiJk";
        let pass_data = PasswordData::with_password(INVALID_PASS.to_string());
        let rule_result = pv.validate(&pass_data);
        assert_eq!(rule_result.valid(), false);
        assert_eq!(rule_result.details().is_empty(), false);

        let mut rules = create_validate_rules();
        rules.push(Box::new(
            UsernameRule::with_match_backwards_and_ignore_case(true, true),
        ));
        let pv = PasswordValidator::new(rules);
        assert!(pv.validate(&PasswordData::with_password(VALID_PASS.to_string())).valid());
        assert!(
            pv.validate(&PasswordData::with_password_and_user(
                VALID_PASS.to_string(),
                Some(String::new())
            ))
            .valid()
        );

        let pass_data =
            PasswordData::with_password_and_user(VALID_PASS.to_string(), Some(USER.to_string()));
        assert!(pv.validate(&pass_data).valid());

        let pass_data =
            PasswordData::with_password_and_user(INVALID_PASS.to_string(), Some(USER.to_string()));
        assert_eq!(pv.validate(&pass_data).valid(), false);
    }

    fn create_validate_rules() -> Vec<Box<dyn Rule>> {
        let length_rule = LengthRule::new(8, 16);
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];
        let char_rule =
            CharacterCharacteristics::with_rules_and_characteristics(char_rules, 3).unwrap();
        let qwerty_seq_rule =
            IllegalSequenceRule::with_sequence_data(EnglishSequenceData::USQwerty);
        let alpha_seq_rule =
            IllegalSequenceRule::with_sequence_data(EnglishSequenceData::Alphabetical);
        let num_seq_rule = IllegalSequenceRule::with_sequence_data(EnglishSequenceData::Numerical);
        let dup_seq_rule = RepeatCharacterRule::default();

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(char_rule),
            Box::new(length_rule),
            Box::new(qwerty_seq_rule),
            Box::new(alpha_seq_rule),
            Box::new(num_seq_rule),
            Box::new(dup_seq_rule),
        ];
        rules
    }

    #[test]
    fn test_passwords() {
        let validator = create_password_validator();
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // all digits
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "4326789032".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::UpperCase.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                    EnglishCharacterData::Special.error_code(),
                    EnglishSequenceData::USQwerty.error_code(),
                ],
            ),
            // all non-alphanumeric
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "$&!$#@*{{>".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::UpperCase.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                ],
            ),
            // all lowercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "aycdopezss".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::UpperCase.error_code(),
                    EnglishCharacterData::Special.error_code(),
                    dictionary_substring::ERROR_CODE,
                ],
            ),
            // all uppercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "AYCDOPEZSS".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                    EnglishCharacterData::Special.error_code(),
                    dictionary_substring::ERROR_CODE,
                ],
            ),
            // digits and non-alphanumeric
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "@&3*(%5{}^".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::UpperCase.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                ],
            ),
            // digits and lowercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "ay3dop5zss".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::UpperCase.error_code(),
                    EnglishCharacterData::Special.error_code(),
                ],
            ),
            // digits and uppercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "AY3DOP5ZSS".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::LowerCase.error_code(),
                    EnglishCharacterData::Special.error_code(),
                ],
            ),
            // non-alphanumeric and lowercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "a&c*o%ea}s".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::UpperCase.error_code(),
                ],
            ),
            // non-alphanumeric and uppercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "A&C*O%EA}S".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                ],
            ),
            // uppercase and lowercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "AycDOPdsyz".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::Special.error_code(),
                ],
            ),
            // invalid whitespace rule passwords.
            // contains a space
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "AycD Pdsyz".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::Special.error_code(),
                    whitespace::ERROR_CODE,
                ],
            ),
            // contains a tab
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "AycD\tPdsyz".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Digit.error_code(),
                    EnglishCharacterData::Special.error_code(),
                    whitespace::ERROR_CODE,
                ],
            ),
            // invalid length rule passwords
            // too short
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4T3t#".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![length::ERROR_CODE_MIN],
            ),
            // too long
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4t3t#n6574632vbad#@!8".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![length::ERROR_CODE_MAX],
            ),
            // invalid dictionary rule passwords
            // matches dictionary word 'none'
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4t3t#none".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![dictionary::ERROR_CODE],
            ),
            // matches dictionary word 'none' backwards
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4t3t#enon".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![dictionary::ERROR_CODE_REVERSED],
            ),
            // invalid sequence rule passwords
            // matches sequence 'zxcvb'
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4zxcvb#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![EnglishSequenceData::USQwerty.error_code()],
            ),
            // matches sequence 'werty' backwards 'wert' is a dictionary word
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4ytrew#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![EnglishSequenceData::USQwerty.error_code(), dictionary::ERROR_CODE_REVERSED],
            ),
            // matches sequence 'iop[]' ignore case
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4iOP[]#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![EnglishSequenceData::USQwerty.error_code()],
            ),
            // invalid userid rule passwords
            // contains userid 'testuser', 'test' and 'user' are dictionary words
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4testuser#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![username::ERROR_CODE, dictionary::ERROR_CODE],
            ),
            // contains userid 'testuser' backwards 'test' and 'user' are dictionary words
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4resutset#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![username::ERROR_CODE_REVERSED, dictionary::ERROR_CODE_REVERSED],
            ),
            // contains userid 'testuser' ignore case 'test' and 'user' are dictionary words
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4TeStusEr#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![username::ERROR_CODE, dictionary::ERROR_CODE],
            ),
            // invalid history rule passwords
            // contains history password
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "t3stUs3r02".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![history::ERROR_CODE],
            ),
            // contains history password
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "t3stUs3r03".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![history::ERROR_CODE],
            ),
            // contains source password
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "t3stUs3r04".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![source::ERROR_CODE],
            ),
            // valid passwords
            // digits, non-alphanumeric, lowercase, uppercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4T3t#N65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![],
            ),
            // digits, non-alphanumeric, lowercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4t3t#n65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![],
            ),
            // digits, non-alphanumeric, uppercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "P4T3T#N65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![],
            ),
            // digits, uppercase, lowercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "p4t3tCn65".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![],
            ),
            // non-alphanumeric, lowercase, uppercase
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "pxT%t#Nwq".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![],
            ),
            // Issue 135
            RulePasswordTestItem(
                Box::new(validator.clone()),
                PasswordData::new(
                    "1234567".to_string(),
                    Some(USER.to_string()),
                    create_password_references(),
                ),
                vec![
                    ERROR_CODE,
                    EnglishCharacterData::Special.error_code(),
                    EnglishCharacterData::LowerCase.error_code(),
                    EnglishCharacterData::UpperCase.error_code(),
                    EnglishSequenceData::Numerical.error_code(),
                    EnglishSequenceData::Numerical.error_code(), // it does the error two times?!
                    length::ERROR_CODE_MIN,
                ],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![RulePasswordTestItem(
            Box::new(create_password_validator()),
            PasswordData::with_password_and_user("ay3dop5zss".to_string(), Some(USER.to_string())),
            vec![
                "INSUFFICIENT_SPECIAL,1,0",
                "INSUFFICIENT_UPPERCASE,1,0",
                "INSUFFICIENT_CHARACTERISTICS,2,4,3",
            ],
        )];
        check_messages(test_cases);
    }

    fn create_password_validator() -> PasswordValidator {
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];
        let char_rule =
            CharacterCharacteristics::with_rules_and_characteristics(char_rules, 3).unwrap();
        let whitespace_rule = WhitespaceRule::default();
        let length_rule = LengthRule::new(8, 16);
        let dict_rule = DictionarySubstringRule::new(create_dictionary(), true);
        let qwerty_seq_rule =
            IllegalSequenceRule::with_sequence_data(EnglishSequenceData::USQwerty);
        let alpha_seq_rule =
            IllegalSequenceRule::with_sequence_data(EnglishSequenceData::Alphabetical);
        let num_seq_rule = IllegalSequenceRule::with_sequence_data(EnglishSequenceData::Numerical);
        let dup_seq_rule = RepeatCharacterRule::default();
        let user_id_rule = UsernameRule::with_match_backwards_and_ignore_case(true, true);
        let history_rule = DigestHistoryRule::new(Sha1Hasher, true);
        let source_rule = DigestSourceRule::new(Sha1Hasher, true);
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(char_rule),
            Box::new(whitespace_rule),
            Box::new(length_rule),
            Box::new(dict_rule),
            Box::new(qwerty_seq_rule),
            Box::new(alpha_seq_rule),
            Box::new(num_seq_rule),
            Box::new(dup_seq_rule),
            Box::new(user_id_rule),
            Box::new(history_rule),
            Box::new(source_rule),
        ];

        PasswordValidator::new(rules)
    }
    fn create_dictionary() -> impl Dictionary {
        let list = create_from_read(
            include_bytes!("../../resources/test/web2-gt3").as_slice(),
            false,
            Some(SliceSort),
        );
        WordListDictionary::new(list)
    }

    fn create_password_references() -> Vec<Box<dyn Reference>> {
        vec![
            Box::new(HistoricalReference::with_password_label(
                "safx/LW8+SsSy/o3PmCNy4VEm5s=".to_string(),
                "history".to_string(),
            )),
            Box::new(HistoricalReference::with_password_label(
                "zurb9DyQ5nooY1la8h86Bh0n1iw=".to_string(),
                "history".to_string(),
            )),
            Box::new(HistoricalReference::with_password_label(
                "bhqabXwE3S8E6xNJfX/d76MFOCs=".to_string(),
                "history".to_string(),
            )),
            Box::new(SourceReference::with_password_label(
                "CJGTDMQRP+rmHApkcijC80aDV0o=".to_string(),
                "source".to_string(),
            )),
        ]
    }
}

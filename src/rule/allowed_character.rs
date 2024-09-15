use crate::rule::allowed_character::MatchBehavior::Contains;
use crate::rule::password_utils::count_matching_characters;
use crate::rule::rule_result::{CountCategory, RuleResult, RuleResultMetadata};
use crate::rule::{PasswordData, Rule};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use MatchBehavior::{EndsWith, StartsWith};

const ERROR_CODE: &str = "ALLOWED_CHAR";
pub struct AllowedCharacter {
    allowed_characters: Vec<char>,
    match_behavior: MatchBehavior,
    report_all: bool,
}

impl AllowedCharacter {
    pub fn new(
        allowed_characters: Vec<char>,
        match_behavior: MatchBehavior,
        report_all: bool,
    ) -> Self {
        AllowedCharacter {
            report_all,
            allowed_characters,
            match_behavior,
        }
    }

    pub fn from_chars(allowed_characters: Vec<char>) -> Self {
        AllowedCharacter {
            allowed_characters,
            match_behavior: Contains,
            report_all: true,
        }
    }

    pub fn with_report_all(allowed_characters: Vec<char>, report_all: bool) -> Self {
        AllowedCharacter {
            allowed_characters,
            match_behavior: Contains,
            report_all,
        }
    }

    fn create_rule_result_detail_parameters(&self, c: char) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("illegalCharacter".to_string(), c.to_string());
        map.insert(
            "matchBehavior".to_string(),
            format!("{:?}", self.match_behavior),
        );
        map
    }
    fn create_rule_result_metadata(&self, password_data: &PasswordData) -> RuleResultMetadata {
        let count = count_matching_characters(
            self.allowed_characters.iter().collect::<String>().as_str(),
            password_data.password(),
        );
        RuleResultMetadata::new(CountCategory::Allowed, count)
    }
}
impl Rule for AllowedCharacter {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let mut matches = HashSet::new();
        let text = password_data.password();
        'la: for c in text.chars() {
            let option = self.allowed_characters.iter().find(|&&x| x == c);
            if option.is_none() && !matches.contains(&c) {
                if self.match_behavior == Contains || self.match_behavior.match_text(text, c) {
                    let first_codee = format!("{}.{}", ERROR_CODE.to_string(), c as u32);
                    let codes = [first_codee, ERROR_CODE.to_string()];
                    result.add_error_with_codes(
                        &codes,
                        Some(self.create_rule_result_detail_parameters(c)),
                    );
                    if !self.report_all {
                        break 'la;
                    }
                    matches.insert(c);
                }
            }
        }
        result.set_metadata(self.create_rule_result_metadata(password_data));
        result
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum MatchBehavior {
    StartsWith,
    EndsWith,
    Contains,
}

impl MatchBehavior {
    pub fn match_text(&self, text: &str, c: char) -> bool {
        match self {
            StartsWith => text.starts_with(c),
            EndsWith => text.ends_with(c),
            Contains => text.contains(c),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            StartsWith => "starts with",
            EndsWith => "ends with",
            Contains => "contains",
        }
    }
}

impl Display for MatchBehavior {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::allowed_character::MatchBehavior::{Contains, EndsWith, StartsWith};
    use crate::rule::allowed_character::{AllowedCharacter, ERROR_CODE};
    use crate::rule::rule_result::CountCategory;
    use crate::rule::{PasswordData, Rule};
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};
    const ALLOWED_CHARS: &[char] = &[
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    ];
    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("boepselwezz".to_string()),
                vec![],
            ),
            // test invalid password
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("gbwersco4kk".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("gbwersco4kk5kk".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test single match
            RulePasswordTestItem(
                Box::new(AllowedCharacter::with_report_all(
                    ALLOWED_CHARS.to_vec(),
                    false,
                )),
                PasswordData::with_password("gbwersco4kk5kk".to_string()),
                vec![ERROR_CODE],
            ),
            // test duplicate matches
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("gbwersco4kk5kk4".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test match behavior
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    StartsWith,
                    true,
                )),
                PasswordData::with_password("4gbwersco4kk5kk".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    StartsWith,
                    true,
                )),
                PasswordData::with_password("gbwersco4kk".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    EndsWith,
                    true,
                )),
                PasswordData::with_password("gbwersco4kk5kk4".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    EndsWith,
                    true,
                )),
                PasswordData::with_password("gbwersco4kk".to_string()),
                vec![],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("gbwersco4kk".to_string()),
                vec!["ALLOWED_CHAR,Contains,4"],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("gbwersco4kk5kk".to_string()),
                vec!["ALLOWED_CHAR,Contains,4", "ALLOWED_CHAR,Contains,5"],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::with_report_all(
                    ALLOWED_CHARS.to_vec(),
                    false,
                )),
                PasswordData::with_password("gbwersco4kk5kk".to_string()),
                vec!["ALLOWED_CHAR,Contains,4"],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec())),
                PasswordData::with_password("gbwersco4kk5kk4".to_string()),
                vec!["ALLOWED_CHAR,Contains,4", "ALLOWED_CHAR,Contains,5"],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    Contains,
                    true,
                )),
                PasswordData::with_password("gbwer scokkk".to_string()),
                vec!["ALLOWED_CHAR,Contains,ALLOWED_CHAR.32"],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    StartsWith,
                    true,
                )),
                PasswordData::with_password("4bwersco4kk".to_string()),
                vec!["ALLOWED_CHAR,StartsWith,4"],
            ),
            RulePasswordTestItem(
                Box::new(AllowedCharacter::new(
                    ALLOWED_CHARS.to_vec(),
                    EndsWith,
                    true,
                )),
                PasswordData::with_password("gbwersco4kk4".to_string()),
                vec!["ALLOWED_CHAR,EndsWith,4"],
            ),
        ];
        check_messages(test_cases)
    }

    #[test]
    fn test_metadata() {
        let rule = AllowedCharacter::from_chars(ALLOWED_CHARS.to_vec());
        let result = rule.validate(&PasswordData::with_password("metadata".to_string()));
        assert!(result.valid());
        let category = CountCategory::Allowed;
        assert_eq!(8, result.metadata().get_count(category).unwrap());

        let result = rule.validate(&PasswordData::with_password("metaDATA".to_string()));
        assert_eq!(false, result.valid());
        assert_eq!(4, result.metadata().get_count(category).unwrap());
    }
}

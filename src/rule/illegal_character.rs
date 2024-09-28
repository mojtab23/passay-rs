use crate::rule::allowed_character::MatchBehavior;
use crate::rule::allowed_character::MatchBehavior::Contains;
use crate::rule::password_utils::count_matching_characters;
use crate::rule::rule_result::{CountCategory, RuleResult, RuleResultMetadata};
use crate::rule::{PasswordData, Rule};
use std::collections::{HashMap, HashSet};

const ERROR_CODE: &str = "ILLEGAL_CHAR";
pub struct IllegalCharacterRule {
    illegal_characters: Vec<char>,
    match_behavior: MatchBehavior,
    report_all: bool,
}

impl IllegalCharacterRule {
    pub fn new(
        illegal_characters: Vec<char>,
        match_behavior: MatchBehavior,
        report_all: bool,
    ) -> Self {
        Self {
            report_all,
            illegal_characters,
            match_behavior,
        }
    }

    pub fn from_chars(illegal_characters: Vec<char>) -> Self {
        Self {
            illegal_characters,
            match_behavior: Contains,
            report_all: true,
        }
    }

    pub fn with_report_all(illegal_characters: Vec<char>, report_all: bool) -> Self {
        Self {
            illegal_characters,
            match_behavior: Contains,
            report_all,
        }
    }
    fn create_rule_result_detail_parameters(&self, c: char) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(2);
        map.insert("illegalCharacter".to_string(), c.to_string());
        map.insert(
            "matchBehavior".to_string(),
            format!("{:?}", self.match_behavior),
        );
        map
    }

    fn create_rule_result_metadata(&self, password_data: &PasswordData) -> RuleResultMetadata {
        let count = count_matching_characters(
            self.illegal_characters.iter().collect::<String>().as_str(),
            password_data.password(),
        );
        RuleResultMetadata::new(CountCategory::Illegal, count)
    }
}

impl Rule for IllegalCharacterRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let text = password_data.password();
        let mut matches = HashSet::with_capacity(text.chars().count());
        for &c in &self.illegal_characters {
            if self.match_behavior.match_text(text, c) && !matches.contains(&c) {
                let codes = vec![format!("{ERROR_CODE}.{}", c as u32), ERROR_CODE.to_string()];
                result.add_error_with_codes(
                    &codes,
                    Some(self.create_rule_result_detail_parameters(c)),
                );
                if !self.report_all {
                    break;
                }
                matches.insert(c);
            }
        }
        result.set_metadata(self.create_rule_result_metadata(password_data));
        result
    }
}
#[cfg(test)]
mod tests {
    use crate::rule::allowed_character::MatchBehavior::{Contains, EndsWith, StartsWith};
    use crate::rule::illegal_character::{IllegalCharacterRule, ERROR_CODE};
    use crate::rule::rule_result::CountCategory::Illegal;
    use crate::rule::{PasswordData, Rule};
    use crate::test::RulePasswordTestItem;

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycDPdsyz".to_string()),
                vec![],
            ),
            // test invalid password
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycD@Pdsyz".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycD@Pd$yz".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test single match
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::with_report_all(vec!['@', '$'], false)),
                PasswordData::with_password("AycD@Pd$yz".to_string()),
                vec![ERROR_CODE],
            ),
            // test duplicate matches
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycD@Pd$yz@".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test match behavior
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(vec!['@', '$'], StartsWith, true)),
                PasswordData::with_password("@ycDAPdSyz&".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(vec!['@', '$'], StartsWith, true)),
                PasswordData::with_password("AycD@Pdsyz".to_string()),
                vec![],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(vec!['@', '$'], EndsWith, true)),
                PasswordData::with_password("AycDAPdSyz@".to_string()),
                vec![ERROR_CODE],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(vec!['@', '$'], EndsWith, true)),
                PasswordData::with_password("AycD@Pdsyz".to_string()),
                vec![],
            ),
        ];
    }
    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycD@Pdsyz".to_string()),
                vec!["ILLEGAL_CHAR,@"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycD@Pd$yz".to_string()),
                vec!["ILLEGAL_CHAR,@", "ILLEGAL_CHAR,$"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::with_report_all(vec!['@', '$'], false)),
                PasswordData::with_password("AycD@Pd$yz".to_string()),
                vec!["ILLEGAL_CHAR,@"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::from_chars(vec!['@', '$'])),
                PasswordData::with_password("AycD@Pd$yz@".to_string()),
                vec!["ILLEGAL_CHAR,@", "ILLEGAL_CHAR,$"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(
                    vec!['@', '$', ' '],
                    Contains,
                    true,
                )),
                PasswordData::with_password("AycD Pdsyz".to_string()),
                vec!["ILLEGAL_CHAR, "],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(vec!['@', '$'], StartsWith, true)),
                PasswordData::with_password("@ycDAPdsyz".to_string()),
                vec!["ILLEGAL_CHAR,@"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalCharacterRule::new(vec!['@', '$'], EndsWith, true)),
                PasswordData::with_password("AycDAPdsyz$".to_string()),
                vec!["ILLEGAL_CHAR,$"],
            ),
        ];
    }
    #[test]
    fn check_metadata() {
        let rule = IllegalCharacterRule::from_chars(vec!['@', '$']);
        let result = rule.validate(&PasswordData::with_password("metadata".to_string()));
        assert!(result.valid());
        let option = result.metadata().get_count(Illegal).unwrap();
        assert_eq!(0, option);

        let result = rule.validate(&PasswordData::with_password("meta@data$".to_string()));
        assert_eq!(false, result.valid());
        let option = result.metadata().get_count(Illegal).unwrap();
        assert_eq!(2, option);
    }
}

use crate::rule::illegal_regex::IllegalRegex;
use crate::rule::rule_result::RuleResult;
use crate::rule::{PasswordData, Rule};
use fancy_regex::Regex;

pub const ERROR_CODE: &str = "ILLEGAL_MATCH";
const DEFAULT_SEQUENCE_LENGTH: usize = 5;
const MINIMUM_SEQUENCE_LENGTH: usize = 3;

// TODO rewrite it without regex
pub struct RepeatCharacterRegexRule {
    regex_rule: IllegalRegex,
}

impl RepeatCharacterRegexRule {
    pub fn new(sequence_length: usize, report_all: bool) -> Result<Self, String> {
        if sequence_length < MINIMUM_SEQUENCE_LENGTH {
            return Err(format!(
                "sequence length must be >= {MINIMUM_SEQUENCE_LENGTH}"
            ));
        }
        let regex_rule = IllegalRegex::new(Self::create_regex(sequence_length), report_all);
        Ok(Self { regex_rule })
    }
    pub fn with_sequence_len(sequence_len: usize) -> Result<Self, String> {
        Self::new(sequence_len, true)
    }

    fn create_regex(sequence_len: usize) -> Regex {
        let sl = sequence_len - 1;
        let string = format!(r"([^\x00-\x1F])\1{{{sl}}}");
        Regex::new(&string).unwrap()
    }
}

impl Rule for RepeatCharacterRegexRule {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        self.regex_rule.validate(password_data)
    }
}

impl Default for RepeatCharacterRegexRule {
    fn default() -> Self {
        RepeatCharacterRegexRule::new(DEFAULT_SEQUENCE_LENGTH, true).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::repeat_character_regex::{RepeatCharacterRegexRule, ERROR_CODE};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test repeating character
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test longer repeating character
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4vvvvvvv#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test valid password for long regex
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::with_sequence_len(7).unwrap()),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // test long regex with short repeat
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::with_sequence_len(7).unwrap()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec![],
            ),
            // test long regex with long repeat
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::with_sequence_len(7).unwrap()),
                PasswordData::with_password("p4vvvvvvv#n65".to_string()),
                vec![ERROR_CODE],
            ),
            // test multiple matches
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
            // test single match
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::new(5, false).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec![ERROR_CODE],
            ),
            // test duplicate matches
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFFQr1&&&&&".to_string()),
                vec![ERROR_CODE, ERROR_CODE],
            ),
        ];

        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4&&&&&#n65".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&", "ILLEGAL_MATCH,FFFFF"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::new(5, false).unwrap()),
                PasswordData::with_password("p4&&&&&#n65FFFFF".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&"],
            ),
            RulePasswordTestItem(
                Box::new(RepeatCharacterRegexRule::default()),
                PasswordData::with_password("p4&&&&&#n65FFFFFQr1&&&&&".to_string()),
                vec!["ILLEGAL_MATCH,&&&&&", "ILLEGAL_MATCH,FFFFF"],
            ),
        ];
        check_messages(test_cases);
    }
}

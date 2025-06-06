use crate::dictionary::Dictionary;
use crate::rule::rule_result::RuleResult;
use crate::rule::{DictionaryRuleTrait, PasswordData, Rule};
use std::collections::HashMap;

pub(crate) const ERROR_CODE: &str = "ILLEGAL_WORD";
pub(crate) const ERROR_CODE_REVERSED: &str = "ILLEGAL_WORD_REVERSED";

pub struct DictionaryRule<D: Dictionary> {
    dictionary: D,
    match_backwards: bool,
}

impl<D: Dictionary> DictionaryRule<D> {
    pub fn new(dictionary: D, match_backwards: bool) -> Self {
        Self {
            dictionary,
            match_backwards,
        }
    }
    pub fn from_dictionary(dictionary: D) -> Self {
        Self {
            dictionary,
            match_backwards: false,
        }
    }
    fn do_word_search(&self, text: &str) -> Option<String> {
        match self.dictionary.search(text) {
            true => Some(text.to_string()),
            false => None,
        }
    }
    fn create_rule_result_detail_parameters(&self, matching_word: &str) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("matchingWord".to_string(), matching_word.to_string());
        map
    }
}

impl<D: Dictionary> Rule for DictionaryRule<D> {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let text = password_data.password();
        let matching_word = self.do_word_search(text);
        if let Some(m) = matching_word {
            result.add_error(
                ERROR_CODE,
                Some(self.create_rule_result_detail_parameters(&m)),
            )
        }
        if self.match_backwards && text.len() > 1 {
            let text = text.chars().rev().collect::<String>();
            let matching_word = self.do_word_search(&text);
            if let Some(m) = matching_word {
                result.add_error(
                    ERROR_CODE_REVERSED,
                    Some(self.create_rule_result_detail_parameters(&m)),
                )
            }
        }
        result
    }
    fn as_dictionary_rule<'a>(&'a self) -> Option<&'a dyn DictionaryRuleTrait> {
        Some(self)
    }
}

impl<D: Dictionary> DictionaryRuleTrait for DictionaryRule<D> {
    fn dictionary(&self) -> &dyn Dictionary {
        &self.dictionary
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::dictionary::word_lists::word_list_dictionary::WordListDictionary;
    use crate::dictionary::word_lists::ArrayWordList;
    use crate::dictionary::DictionaryBuilder;
    use crate::rule::dictionary::{DictionaryRule, ERROR_CODE, ERROR_CODE_REVERSED};
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    fn create_rule() -> Box<DictionaryRule<WordListDictionary<ArrayWordList>>> {
        let case_sensitive_dict = DictionaryBuilder::new()
            .add_read(Box::new(read_word_list()))
            .case_sensitive(true)
            .build();
        Box::new(DictionaryRule::from_dictionary(case_sensitive_dict))
    }

    pub(crate) fn read_word_list() -> &'static [u8] {
        include_bytes!("../../resources/test/web2")
    }

    fn create_backward_rule() -> Box<DictionaryRule<WordListDictionary<ArrayWordList>>> {
        let case_sensitive_dict = DictionaryBuilder::new()
            .add_read(Box::new(read_word_list()))
            .case_sensitive(true)
            .build();
        Box::new(DictionaryRule::new(case_sensitive_dict, true))
    }
    fn create_ignore_case_rule() -> Box<DictionaryRule<WordListDictionary<ArrayWordList>>> {
        let case_insensitive_dict =
            DictionaryBuilder::new().add_read(Box::new(read_word_list())).build();
        Box::new(DictionaryRule::from_dictionary(case_insensitive_dict))
    }
    fn create_all_rule() -> Box<DictionaryRule<WordListDictionary<ArrayWordList>>> {
        let case_insensitive_dict =
            DictionaryBuilder::new().add_read(Box::new(read_word_list())).build();
        Box::new(DictionaryRule::new(case_insensitive_dict, true))
    }

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // test valid password
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("Pullm@n1z3".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("Pullmanize".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("ezinamlluP".to_string()),
                vec![],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("PuLLmanIZE".to_string()),
                vec![],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("EZInamLLuP".to_string()),
                vec![],
            ),
            // valid password
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("Pullm@n1z3".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("Pullmanize".to_string()),
                vec![ERROR_CODE],
            ),
            // backward dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("ezinamlluP".to_string()),
                vec![ERROR_CODE_REVERSED],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("PuLLmanIZE".to_string()),
                vec![],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("EZInamLLuP".to_string()),
                vec![],
            ),
            // valid password
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("Pullm@n1z3".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("Pullmanize".to_string()),
                vec![ERROR_CODE],
            ),
            // backward dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("ezinamlluP".to_string()),
                vec![],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("PuLLmanIZE".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("EZInamLLuP".to_string()),
                vec![],
            ),
            // valid password
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("Pullm@n1z3".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("Pullmanize".to_string()),
                vec![ERROR_CODE],
            ),
            // backward dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("ezinamlluP".to_string()),
                vec![ERROR_CODE_REVERSED],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("PuLLmanIZE".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("EZInamLLuP".to_string()),
                vec![ERROR_CODE_REVERSED],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("Pullmanize".to_string()),
                vec!["ILLEGAL_WORD,Pullmanize"],
            ),
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("ezinamlluP".to_string()),
                vec!["ILLEGAL_WORD_REVERSED,Pullmanize"],
            ),
        ];
        check_messages(test_cases);
    }
}

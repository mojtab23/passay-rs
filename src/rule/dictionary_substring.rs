use crate::dictionary::Dictionary;
use crate::rule::rule_result::RuleResult;
use crate::rule::{DictionaryRuleTrait, PasswordData, Rule};
use std::collections::HashMap;

pub(crate) const ERROR_CODE: &str = "ILLEGAL_WORD";
const ERROR_CODE_REVERSED: &str = "ILLEGAL_WORD_REVERSED";

pub struct DictionarySubstringRule<D: Dictionary> {
    dictionary: D,
    match_backwards: bool,
}

impl<D: Dictionary> DictionarySubstringRule<D> {
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
        for i in 1..=text.len() {
            let mut j = 0usize;
            while j + i <= text.len() {
                let s = &text[j..j + i];
                if self.dictionary.search(s) {
                    return Some(s.to_string());
                }
                j += 1;
            }
        }
        None
    }
    fn create_rule_result_detail_parameters(&self, matching_word: &str) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(1);
        map.insert("matchingWord".to_string(), matching_word.to_string());
        map
    }
}

impl<D: Dictionary> Rule for DictionarySubstringRule<D> {
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
impl<D: Dictionary> DictionaryRuleTrait for DictionarySubstringRule<D> {
    fn dictionary(&self) -> &dyn Dictionary {
        &self.dictionary
    }
}
#[cfg(test)]
mod tests {
    use crate::dictionary::word_lists::sort::SliceSort;
    use crate::dictionary::word_lists::word_list_dictionary::WordListDictionary;
    use crate::dictionary::word_lists::{create_from_read, ArrayWordList};
    use crate::rule::dictionary_substring::{
        DictionarySubstringRule, ERROR_CODE, ERROR_CODE_REVERSED,
    };
    use crate::rule::PasswordData;
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            // valid password
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("p4t3t#7wd5gew".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("p4tlancely5gew".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("p4tylecnal5gew".to_string()),
                vec![],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("p4tlAnCeLy5gew".to_string()),
                vec![],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_rule(),
                PasswordData::with_password("p4tyLeCnAl5gew".to_string()),
                vec![],
            ),
            // valid password
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("p4t3t#7wd5gew".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("p4tlancely5gew".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("p4tylecnal5gew".to_string()),
                vec![ERROR_CODE_REVERSED],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("p4tlAnCeLy5gew".to_string()),
                vec![],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("p4tyLeCnAl5gew".to_string()),
                vec![],
            ),
            // valid password
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("p4t3t#7wd5gew".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("p4tlancely5gew".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("p4tylecnal5gew".to_string()),
                vec![],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("p4tlAnCeLy5gew".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_ignore_case_rule(),
                PasswordData::with_password("p4tyLeCnAl5gew".to_string()),
                vec![],
            ),
            // valid password
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("p4t3t#7wd5gew".to_string()),
                vec![],
            ),
            // dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("p4tlancely5gew".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("p4tylecnal5gew".to_string()),
                vec![ERROR_CODE_REVERSED],
            ),
            // mixed case dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("p4tlAnCeLy5gew".to_string()),
                vec![ERROR_CODE],
            ),
            // backwards mixed case dictionary word
            RulePasswordTestItem(
                create_all_rule(),
                PasswordData::with_password("p4tyLeCnAl5gew".to_string()),
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
                PasswordData::with_password("p4tlancely5gew".to_string()),
                vec!["ILLEGAL_WORD,lance"],
            ),
            RulePasswordTestItem(
                create_backward_rule(),
                PasswordData::with_password("p4tylecnal5gew".to_string()),
                vec!["ILLEGAL_WORD_REVERSED,lance"],
            ),
        ];
        check_messages(test_cases);
    }
    fn create_rule() -> Box<DictionarySubstringRule<WordListDictionary<ArrayWordList>>> {
        let case_sensitive_word_list = create_from_read(read_word_list(), true, Some(SliceSort));
        let case_sensitive_dict = WordListDictionary::new(case_sensitive_word_list);
        Box::new(DictionarySubstringRule::from_dictionary(
            case_sensitive_dict,
        ))
    }

    fn create_backward_rule() -> Box<DictionarySubstringRule<WordListDictionary<ArrayWordList>>> {
        let case_sensitive_word_list = create_from_read(read_word_list(), true, Some(SliceSort));
        let case_sensitive_dict = WordListDictionary::new(case_sensitive_word_list);
        Box::new(DictionarySubstringRule::new(case_sensitive_dict, true))
    }

    fn create_ignore_case_rule() -> Box<DictionarySubstringRule<WordListDictionary<ArrayWordList>>>
    {
        let case_insensitive_word_list = create_from_read(read_word_list(), false, Some(SliceSort));
        let case_insensitive_dict = WordListDictionary::new(case_insensitive_word_list);
        Box::new(DictionarySubstringRule::from_dictionary(
            case_insensitive_dict,
        ))
    }
    fn create_all_rule() -> Box<DictionarySubstringRule<WordListDictionary<ArrayWordList>>> {
        let case_insensitive_word_list = create_from_read(read_word_list(), false, Some(SliceSort));
        let case_insensitive_dict = WordListDictionary::new(case_insensitive_word_list);
        Box::new(DictionarySubstringRule::new(case_insensitive_dict, true))
    }
    fn read_word_list() -> &'static [u8] {
        include_bytes!("../../resources/test/web2-gt3")
    }
}

use crate::dictionary::word_lists::sort::SliceSort;
use crate::dictionary::word_lists::word_list_dictionary::WordListDictionary;
use crate::dictionary::word_lists::{create_from_reads, ArrayWordList};
use std::io::Read;

pub mod ternary_tree;
pub mod word_lists;

pub trait Dictionary {
    fn search(&self, word: &str) -> bool;
    fn len(&self) -> usize;
}

pub struct DictionaryBuilder {
    reads: Vec<Box<dyn Read>>,
    case_sensitive: bool,
}

impl Default for DictionaryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DictionaryBuilder {
    pub fn build(self) -> WordListDictionary<ArrayWordList> {
        let case_sensitive = self.case_sensitive;
        let word_list = create_from_reads(self.reads, case_sensitive, Some(SliceSort));
        WordListDictionary::new(word_list)
    }

    pub fn add_read(mut self, read: Box<dyn Read>) -> DictionaryBuilder {
        self.reads.push(read);
        self
    }

    pub fn case_sensitive(mut self, case_sensitive: bool) -> DictionaryBuilder {
        self.case_sensitive = case_sensitive;
        self
    }

    pub fn new() -> Self {
        Self {
            reads: vec![],
            case_sensitive: false,
        }
    }
}

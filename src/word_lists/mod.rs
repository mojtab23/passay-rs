/// Represents a random-access list of words.
use core::slice::Iter;
use std::io::prelude::*;
use std::io::{BufReader, Read};
use std::ops::Index;

use crate::word_lists::array_word_list::ArrayWordList;
use crate::word_lists::sort::ArraySorter;

mod array_word_list;
mod sort;

pub trait WordLists: Index<usize> {
    /// Returns an iterator to traverse this word list from the 0th index.
    /// @return  iterator for this word list
    fn iter() -> Iter<'static, &'static str>;

    /// Returns an iterator to traverse this word list by following a recursive sequence of medians.
    /// @return  iterator for this word list
    fn medians_iter() -> Iter<'static, &'static str>;

    /// Returns the number of words in the list.
    /// @return  total number of words in list.
    fn len(&self) -> usize;
}

/// Creates an [ArrayWordList] by reading the contents of the given read with support for sorting the contents.
pub fn create_from_read(
    read: impl Read,
    case_sensitive: bool,
    sorter: impl ArraySorter,
) -> ArrayWordList {
    let reader = BufReader::new(read);
    let words: Vec<String> = reader
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect();
    ArrayWordList::with_sorter(words, case_sensitive, Some(sorter))
}

/// Reads words, one per line, from a Read and returns a word list.
pub fn read_words(read: impl Read) -> Vec<String> {
    let reader = BufReader::new(read);
    reader
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

#[cfg(test)]
mod tests {

    use crate::word_lists::sort::SliceSort;
    use crate::word_lists::{create_from_read, read_words, WordLists};

    #[test]
    fn create_from_reader() {
        let words = vec![
            " leading whitespace",
            " surrounding whitespace ",
            "bar",
            "foo",
            "trailing whitespace ",
        ];

        let mut all_string = String::new();
        for word in words.iter() {
            all_string.push_str(word);
            all_string.push('\n');
        }
        let word_list = create_from_read(all_string.as_bytes(), true, SliceSort::default());
        for i in 0..word_list.len() {
            assert_eq!(words[i], word_list[i]);
        }
    }

    #[test]
    fn test_words_from_read() {
        let sorted_file = include_str!("../../resources/test/eign");
        let words = read_words(sorted_file.as_bytes());
        let good = "good".to_string();
        assert!(words.contains(&good));
    }
}

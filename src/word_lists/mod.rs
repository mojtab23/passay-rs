/// Represents a random-access list of words.
use core::slice::Iter;
use std::cmp::Ordering;
use std::io::prelude::*;
use std::io::{BufReader, Read};
use std::ops::Index;

use crate::word_lists::array_word_list::ArrayWordList;
use crate::word_lists::sort::{ArraySorter, Comparator};

mod array_word_list;
mod sort;

pub trait WordLists: Index<usize, Output = String> {
    /// Returns an iterator to traverse this word list from the 0th index.
    /// @return  iterator for this word list
    fn iter() -> Iter<'static, &'static str>;

    /// Returns an iterator to traverse this word list by following a recursive sequence of medians.
    /// @return  iterator for this word list
    fn medians_iter() -> Iter<'static, &'static str>;

    /// Returns the number of words in the list.
    /// @return  total number of words in list.
    fn len(&self) -> usize;

    /// Returns the comparator that should be used to compare a search term with candidate words in the list.
    /// The comparator naturally respects ordering and case sensitivity of the word list.
    fn get_comparator(&self) -> Comparator;
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

/// Performs a binary search of the given word list for the given word.
pub fn binary_search(word_list: impl WordLists, word: &str) -> Option<usize> {
    let mut low = 0usize;
    let mut high = word_list.len() - 1;
    let mut mid: usize;

    while low <= high {
        mid = (low + high) / 2;
        let x = &word_list[mid];
        let ordering = (word_list.get_comparator())(x, word);
        match ordering {
            Ordering::Less => low = mid + 1,
            Ordering::Equal => return Some(mid),
            Ordering::Greater => high = mid - 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::word_lists::array_word_list::ArrayWordList;
    use crate::word_lists::sort::SliceSort;
    use crate::word_lists::{binary_search, create_from_read, read_words, WordLists};

    fn case_sensitive_word_list() -> ArrayWordList {
        create_from_read(
            include_bytes!("../../resources/test/freebsd").as_slice(),
            true,
            SliceSort::default(),
        )
    }

    fn case_insensitive_word_list() -> ArrayWordList {
        create_from_read(
            include_bytes!("../../resources/test/web2").as_slice(),
            false,
            SliceSort::default(),
        )
    }

    fn one_word() -> ArrayWordList {
        ArrayWordList::with_words(["a"].map(String::from).to_vec())
    }

    fn two_words() -> ArrayWordList {
        ArrayWordList::with_words(["a", "b"].map(String::from).to_vec())
    }

    fn three_words() -> ArrayWordList {
        ArrayWordList::with_words(["a", "b", "c"].map(String::from).to_vec())
    }

    fn create_search_data() -> [(ArrayWordList, &'static str, Option<usize>); 13] {
        [
            (one_word(), "a", Some(0)),
            (one_word(), "b", None),
            (two_words(), "a", Some(0)),
            (two_words(), "b", Some(1)),
            (two_words(), "c", None),
            (three_words(), "a", Some(0)),
            (three_words(), "b", Some(1)),
            (three_words(), "c", Some(2)),
            (three_words(), "d", None),
            (case_sensitive_word_list(), "ISBN", Some(76)),
            (case_sensitive_word_list(), "guacamole", None),
            (case_insensitive_word_list(), "irresolute", Some(98323)),
            (case_insensitive_word_list(), "brujo", None),
        ]
    }

    #[test]
    fn test_binary_search() {
        let search_data = create_search_data();
        for (wl, word, i) in search_data {
            assert_eq!(i, binary_search(wl, word));
        }
    }

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

    // We don't have a implementation WordLists#readWords(InputStream, String, List)
    // We don't have a implementation WordLists#readZippedWords(InputStream, String, String, List)
}

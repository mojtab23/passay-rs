/// Represents a random-access list of words.
use core::slice::Iter;
use std::cmp::Ordering;

use std::io::{BufReader, Read};
use std::ops::Index;

pub use self::array_word_list::ArrayWordList;
use self::sort::{ArraySorter, Comparator};

mod array_word_list;
pub mod sort;
mod test_base;
pub mod word_list_dictionary;

pub trait WordLists: Index<usize, Output = String> {
    /// Returns an iterator to traverse this word list from the 0th index.
    /// @return  iterator for this word list
    fn iter(&self) -> Iter<'_, String>;

    // /// Returns an iterator to traverse this word list by following a recursive sequence of medians.
    // /// @return  iterator for this word list
    // fn medians_iter(&self) -> Iter<'static, &'static str>;

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
    sorter: Option<impl ArraySorter>,
) -> ArrayWordList {
    let mut reader = BufReader::new(read);
    let mut s = String::new();
    let _ = reader.read_to_string(&mut s);
    let s = s.replace('\r', "\n");
    let words: Vec<String> = s.lines().map(String::from).filter(|s| !s.is_empty()).collect();
    ArrayWordList::with_sorter(words, case_sensitive, sorter)
}

/// Creates an [ArrayWordList] by reading the contents of the given reads with support for sorting the contents.
pub fn create_from_reads(
    reads: Vec<Box<dyn Read>>,
    case_sensitive: bool,
    sorter: Option<impl ArraySorter>,
) -> ArrayWordList {
    let mut words = vec![];
    for read in reads {
        read_word_list(read, &mut words);
    }
    ArrayWordList::with_sorter(words, case_sensitive, sorter)
}

/// Add words to word list
fn read_word_list(read: Box<dyn Read>, words: &mut Vec<String>) {
    let vec = read_words(read);
    words.extend(vec);
}

/// Reads words, one per line, from a Read and returns a word list.
pub fn read_words(read: Box<dyn Read>) -> Vec<String> {
    let mut reader = BufReader::new(read);
    let mut s = String::new();
    let _ = reader.read_to_string(&mut s);
    let s = s.replace('\r', "\n");
    s.lines().map(String::from).collect()
}

/// Performs a binary search of the given word list for the given word.
pub fn binary_search(word_list: &impl WordLists, word: &str) -> Option<usize> {
    let mut size = word_list.len();
    let mut left = 0;
    let mut right = size;
    while left < right {
        let mid = left + size / 2;

        let x = &word_list[mid];
        let cmp = word_list.get_comparator()(x, word);
        left = if cmp == Ordering::Less { mid + 1 } else { left };
        right = if cmp == Ordering::Greater { mid } else { right };
        if cmp == Ordering::Equal {
            return Some(mid);
        }

        size = right - left;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::array_word_list::ArrayWordList;
    use super::sort::SliceSort;
    use super::{binary_search, create_from_read, read_words, WordLists};

    fn case_sensitive_word_list() -> ArrayWordList {
        create_from_read(
            include_bytes!("../../../resources/test/freebsd").as_slice(),
            true,
            Some(SliceSort),
        )
    }

    fn case_insensitive_word_list() -> ArrayWordList {
        create_from_read(
            include_bytes!("../../../resources/test/web2").as_slice(),
            false,
            Some(SliceSort),
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
            assert_eq!(i, binary_search(&wl, word));
        }
    }

    #[test]
    fn create_from_reader() {
        let words = [
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
        let word_list = create_from_read(all_string.as_bytes(), true, Some(SliceSort));
        for i in 0..word_list.len() {
            assert_eq!(words[i], word_list[i]);
        }
    }

    #[test]
    fn test_words_from_read() {
        let sorted_file = include_str!("../../../resources/test/eign");
        let words = read_words(Box::new(sorted_file.as_bytes()));
        let good = "good".to_string();
        assert!(words.contains(&good));
    }

    // We don't have a implementation WordLists#readWords(InputStream, String, List)
    // We don't have a implementation WordLists#readZippedWords(InputStream, String, String, List)
}

use std::cmp::Ordering;
use std::ops::Index;
use std::slice::Iter;

use crate::word_lists::sort::{ArraySorter, Comparator, SliceSort};
use crate::word_lists::WordLists;

pub fn case_sensitive_comparator(a: &str, b: &str) -> Ordering {
    a.cmp(b)
}

pub fn case_insensitive_comparator(a: &str, b: &str) -> Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}

pub struct ArrayWordList {
    words: Vec<String>,
    case_sensitive: bool,
    comparator: fn(&str, &str) -> Ordering,
}

impl ArrayWordList {
    /// Creates a new word list backed by the given vector with optional sorter.
    pub fn with_sorter(
        mut words: Vec<String>,
        case_sensitive: bool,
        sorter: Option<impl ArraySorter>,
    ) -> Self {
        let comparator = if case_sensitive {
            case_sensitive_comparator
        } else {
            case_insensitive_comparator
        };

        if let Some(sort) = sorter {
            sort.sort_with_comparator(&mut words[..], comparator)
        }

        ArrayWordList {
            words,
            case_sensitive,
            comparator,
        }
    }

    /// Creates a new word list backed by the given array.
    pub fn new(words: Vec<String>, case_sensitive: bool) -> Self {
        Self::with_sorter(words, case_sensitive, Option::<SliceSort>::None)
    }

    /// Creates a new case-sensitive word list backed by the given vector.
    pub fn with_words(words: Vec<String>) -> Self {
        Self::new(words, true)
    }
}

impl WordLists for ArrayWordList {
    fn iter() -> Iter<'static, &'static str> {
        todo!()
    }

    fn medians_iter() -> Iter<'static, &'static str> {
        todo!()
    }

    fn len(&self) -> usize {
        self.words.len()
    }

    fn get_comparator(&self) -> Comparator {
        self.comparator
    }
}

impl Index<usize> for ArrayWordList {
    type Output = String;

    fn index(&self, index: usize) -> &Self::Output {
        &self.words[index]
    }
}

#[cfg(test)]
mod tests {
    use crate::word_lists::array_word_list::ArrayWordList;
    use crate::word_lists::WordLists;

    #[test]
    fn construct() {
        let words = ["a", "b", "", "c"].map(String::from).to_vec();
        let _word_list = ArrayWordList::new(words, true);
    }

    #[test]
    fn words_with_space() {
        let mut vec_with_space = [" Man", " cadet", "!@#$%^&*", "password", "inner ", "outer "];
        vec_with_space.sort();
        let vec_with_space = vec_with_space.map(String::from).to_vec();
        let vec_len = vec_with_space.len();
        let first_in_vec = vec_with_space[0].to_owned();
        let last_in_vec = vec_with_space.last().unwrap().to_owned();

        let wl = ArrayWordList::new(vec_with_space, true);
        assert_eq!(vec_len, wl.len());
        assert_eq!(first_in_vec, wl[0]);
        assert_eq!(last_in_vec, wl[wl.len() - 1]);
    }
}

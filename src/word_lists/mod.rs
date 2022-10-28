/// Represents a random-access list of words.
use core::slice::Iter;
use std::io::Read;
use std::ops;
use std::ops::Index;

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

// impl Index<usize> for WordLists {
//     type Output = String;
//
//     fn index(&self, index: usize) -> &Self::Output {
//
//     }
// }

pub fn create_from_read(_read: &dyn Read, _case_sensitive: bool) {}

#[cfg(test)]
mod tests {

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
        for word in words {
            all_string.push_str(word);
            all_string.push('\n');
        }

        // assert_eq!(result, 4);
    }
}

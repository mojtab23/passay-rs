use crate::dictionary::Dictionary;
use crate::dictionary::word_lists::{WordLists, binary_search};

/// Provides fast searching for dictionary words using a word list. It's critical that the word list provided to this
/// dictionary be sorted according to the natural ordering of {@link java.lang.String}.
/// @author  Middleware Services
#[derive(Debug)]
pub struct WordListDictionary<T>
where
    T: WordLists,
{
    word_list: T,
}

impl<T> WordListDictionary<T>
where
    T: WordLists,
{
    pub fn new(word_list: T) -> WordListDictionary<T> {
        Self { word_list }
    }
}

impl<T> Dictionary for WordListDictionary<T>
where
    T: WordLists,
{
    fn search(&self, word: &str) -> bool {
        binary_search(&self.word_list, word).is_some()
    }

    fn len(&self) -> usize {
        self.word_list.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::dictionary::Dictionary;
    use crate::dictionary::word_lists::sort::SliceSort;
    use crate::dictionary::word_lists::word_list_dictionary::WordListDictionary;
    use crate::dictionary::word_lists::{WordLists, create_from_read};

    const FALSE_SEARCH: &str = "not-found-in-the-dictionary";

    fn create_dictionary(case_sensitive: bool) -> impl Dictionary {
        let list = create_from_read(
            include_bytes!("../../../resources/test/freebsd").as_slice(),
            case_sensitive,
            Some(SliceSort),
        );
        WordListDictionary::new(list)
    }

    #[test]
    fn search() {
        let case_sensitive = create_dictionary(true);
        let case_insensitive = create_dictionary(false);

        assert!(case_sensitive.search("TrustedBSD"));
        assert!(!case_sensitive.search(FALSE_SEARCH));

        assert!(case_insensitive.search("TrustedBSD"));
        assert!(!case_insensitive.search(FALSE_SEARCH));
    }

    #[test]
    fn search_all() {
        let case_sensitive = create_dictionary(true);
        let case_insensitive = create_dictionary(false);
        let words = create_from_read(
            include_bytes!("../../../resources/test/freebsd.sort").as_slice(),
            true,
            Some(SliceSort),
        );
        for word in words.iter() {
            assert!(case_sensitive.search(word));
            assert!(case_insensitive.search(word));
            assert!(case_insensitive.search(&word.to_lowercase()));
            assert!(case_insensitive.search(&word.to_uppercase()));
        }
    }
}

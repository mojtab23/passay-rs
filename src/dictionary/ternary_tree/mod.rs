use std::cmp::Ordering::Equal;

use crate::dictionary::ternary_tree::tree::Tst;
use crate::dictionary::word_lists::WordLists;
use crate::dictionary::Dictionary;

mod tree;

pub struct TernaryTreeDictionary {
    tree: Tst<()>,
}

impl TernaryTreeDictionary {
    pub fn with_wordlist(wordlist: impl WordLists) -> Self {
        Self::with_wordlist_and_median(wordlist)
    }

    pub fn with_wordlist_and_median(wordlist: impl WordLists /*, _use_median: bool*/) -> Self {
        let case_sensitive = (wordlist.get_comparator())("A", "a") != Equal;
        let mut tst = Tst::new(case_sensitive);
        // TODO add median iterator
        for y in wordlist.iter() {
            tst.insert(y, ());
        }
        TernaryTreeDictionary { tree: tst }
    }
}

impl Dictionary for TernaryTreeDictionary {
    fn search(&self, word: &str) -> bool {
        self.tree.get(word).is_some()
    }

    fn len(&self) -> usize {
        self.tree.len()
    }
}

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use crate::dictionary::ternary_tree::TernaryTreeDictionary;
    use crate::dictionary::word_lists::sort::{
        ArraySorter, BubbleSortOptimized, InsertionSort, QuickSort, SelectionSort, SliceSort,
    };
    use crate::dictionary::word_lists::{create_from_read, ArrayWordList, WordLists};
    use crate::dictionary::Dictionary;

    const FALSE_SEARCH: &str = "not-found-in-the-dictionary";
    const ANIMALS: &[&str] = &[
        "Aardvark",
        "Baboon",
        "Chinchilla",
        "Donkey",
        "Emu",
        "Flamingo",
        "Gorilla",
        "Hippopotamus",
        "Iguana",
        "Jackal",
        "Kangaroo",
        "Lemming",
        "Marmot",
        "Narwhal",
        "Ox",
        "Platypus",
        "Quail",
        "Rhinoceros",
        "Skunk",
        "Tortoise",
        "Uakari",
        "Vulture",
        "Walrus",
        "Xantus",
        "Yak",
        "Zebra",
    ];
    const ANIMAL_SEARCH_CS: &str = "Kangaroo";
    const ANIMAL_SEARCH_CI: &str = "kangaroo";
    fn create_dictionary() -> (TernaryTreeDictionary, TernaryTreeDictionary) {
        let case_sensitive = create_from_read(
            include_bytes!("../../../resources/test/web2").as_slice(),
            true,
            Some(SliceSort),
        );
        let case_sensitive = TernaryTreeDictionary::with_wordlist(case_sensitive);

        let case_insensitive = create_from_read(
            include_bytes!("../../../resources/test/web2").as_slice(),
            false,
            Some(SliceSort),
        );
        let case_insensitive = TernaryTreeDictionary::with_wordlist(case_insensitive);
        (case_sensitive, case_insensitive)
    }

    fn create_words() -> ArrayWordList {
        create_from_read(
            include_bytes!("../../../resources/test/web2").as_slice(),
            false,
            Some(SliceSort),
        )
    }

    #[test]
    fn search() {
        let (case_sensitive, case_insensitive) = create_dictionary();
        assert!(case_sensitive.search("manipular"));
        assert!(!case_sensitive.search(FALSE_SEARCH));
        assert!(case_sensitive.search("z"));
        assert!(case_insensitive.search("manipular"));
        let x = "manipular".to_uppercase();
        assert!(case_insensitive.search(&x));
        assert!(!case_insensitive.search(FALSE_SEARCH));
        assert!(case_insensitive.search("z"));
    }

    #[test]
    fn search_all() {
        let (case_sensitive, case_insensitive) = create_dictionary();
        let words = create_words();
        for word in words.iter() {
            assert!(case_sensitive.search(word));
            assert!(case_insensitive.search(word));
            assert!(case_insensitive.search(&word.to_lowercase()));
            assert!(case_insensitive.search(&word.to_uppercase()));
        }
    }

    #[test]
    fn partial_search() {
        // TODO
    }

    #[test]
    fn near_search() {
        // TODO
    }

    fn test_sort(sorter: impl ArraySorter + Clone) {
        let awl = ArrayWordList::with_sorter(get_animals(), true, Some(sorter.clone()));
        let sort_cs = TernaryTreeDictionary::with_wordlist(awl);
        assert!(sort_cs.search(ANIMAL_SEARCH_CS));
        assert!(!sort_cs.search(ANIMAL_SEARCH_CI));
        //TODO ANIMAL_PARTIAL_SEARCH_RESULTS_CS
        //TODO ANIMAL_PARTIAL_SEARCH_RESULTS_CI

        let awl = ArrayWordList::with_sorter(get_animals(), false, Some(sorter));
        let sort_ci = TernaryTreeDictionary::with_wordlist(awl);
        assert!(sort_ci.search(ANIMAL_SEARCH_CS));
        assert!(sort_ci.search(ANIMAL_SEARCH_CI));
    }

    fn get_animals() -> Vec<String> {
        let mut animals: Vec<String> = ANIMALS.iter().map(|a| a.to_string()).collect();
        animals.shuffle(&mut thread_rng());
        animals
    }

    #[test]
    fn bubble_sort() {
        test_sort(BubbleSortOptimized);
    }
    #[test]
    fn selection_sort() {
        test_sort(SelectionSort);
    }
    #[test]
    fn insertion_sort() {
        test_sort(InsertionSort);
    }
    #[test]
    fn quick_sort() {
        test_sort(QuickSort);
    }
}

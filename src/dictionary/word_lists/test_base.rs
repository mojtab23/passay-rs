#![cfg(test)]

use super::array_word_list::ArrayWordList;
use super::sort::SliceSort;
use super::{create_from_read, WordLists};

pub struct ExpectedWord {
    pub word: String,
    pub index: usize,
}

impl ExpectedWord {
    pub fn new(word: String, index: usize) -> Self {
        ExpectedWord { word, index }
    }
}

pub fn provide_word_lists_with_expected_words() -> [(ArrayWordList, usize, Vec<ExpectedWord>); 5] {
    [
        (
            create_from_read(
                include_bytes!("../../../resources/test/dict-enUS.txt").as_slice(),
                true,
                None::<SliceSort>,
            ),
            48029,
            vec![
                ExpectedWord::new("A".to_string(), 0),
                ExpectedWord::new("AA".to_string(), 1),
                ExpectedWord::new("Bernanke".to_string(), 1076),
                ExpectedWord::new("clammily".to_string(), 16264),
                ExpectedWord::new("clamminess".to_string(), 16265),
                ExpectedWord::new("exponential".to_string(), 22000),
                ExpectedWord::new("maple".to_string(), 30256),
                ExpectedWord::new("zymurgy".to_string(), 48028),
            ],
        ),
        (
            create_from_read(
                include_bytes!("../../../resources/test/dict-frFR.txt").as_slice(),
                true,
                None::<SliceSort>,
            ),
            73424,
            vec![
                ExpectedWord::new("A".to_string(), 0),
                ExpectedWord::new("Carol".to_string(), 990),
                ExpectedWord::new("caoutchouc".to_string(), 15866),
                ExpectedWord::new("peinture".to_string(), 50303),
                ExpectedWord::new("retrouvaille".to_string(), 58153),
                ExpectedWord::new("yaourt".to_string(), 70997),
                ExpectedWord::new("œuvée".to_string(), 73423),
            ],
        ),
        (
            create_from_read(
                include_bytes!("../../../resources/test/dict-frFR-cr.txt").as_slice(),
                true,
                None::<SliceSort>,
            ),
            73424,
            vec![
                ExpectedWord::new("A".to_string(), 0),
                ExpectedWord::new("Carol".to_string(), 990),
                ExpectedWord::new("caoutchouc".to_string(), 15866),
                ExpectedWord::new("peinture".to_string(), 50303),
                ExpectedWord::new("retrouvaille".to_string(), 58153),
                ExpectedWord::new("yaourt".to_string(), 70997),
                ExpectedWord::new("œuvée".to_string(), 73423),
            ],
        ),
        (
            create_from_read(
                include_bytes!("../../../resources/test/dict-viVN.txt").as_slice(),
                true,
                None::<SliceSort>,
            ),
            6634,
            vec![
                ExpectedWord::new("a".to_string(), 0),
                ExpectedWord::new("ai".to_string(), 1),
                ExpectedWord::new("giội".to_string(), 1361),
                ExpectedWord::new("giộp".to_string(), 1362),
                ExpectedWord::new("mướt".to_string(), 2763),
                ExpectedWord::new("mười".to_string(), 2764),
                ExpectedWord::new("mường".to_string(), 2765),
                ExpectedWord::new("ực".to_string(), 6632),
                ExpectedWord::new("ỷ".to_string(), 6633),
            ],
        ),
        (
            create_from_read(
                include_bytes!("../../../resources/test/dict-viVN-crlf.txt").as_slice(),
                true,
                None::<SliceSort>,
            ),
            6634,
            vec![
                ExpectedWord::new("a".to_string(), 0),
                ExpectedWord::new("ai".to_string(), 1),
                ExpectedWord::new("giội".to_string(), 1361),
                ExpectedWord::new("giộp".to_string(), 1362),
                ExpectedWord::new("mướt".to_string(), 2763),
                ExpectedWord::new("mười".to_string(), 2764),
                ExpectedWord::new("mường".to_string(), 2765),
                ExpectedWord::new("ực".to_string(), 6632),
                ExpectedWord::new("ỷ".to_string(), 6633),
            ],
        ),
    ]
}

pub fn test_get(list: impl WordLists, expected_size: usize, expected_words: &[ExpectedWord]) {
    dbg!(list.len());
    dbg!(expected_size);
    for ew in expected_words {
        assert_eq!(&ew.word, &list[ew.index]);
    }
    debug_assert!(list.len() <= expected_size);
}

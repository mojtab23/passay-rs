pub mod ternary_tree;
pub mod word_lists;

pub trait Dictionary {
    fn search(&self, word: &str) -> bool;
    fn size(&self) -> usize;
}

pub fn count_matching_characters(characters: &str, input: &str) -> usize {
    input.chars().filter(|&c| characters.contains(c)).count()
}

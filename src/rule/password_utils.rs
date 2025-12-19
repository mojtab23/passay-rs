/// Returns count of the characters in the input string that are also in the characters string.
pub fn count_matching_characters(characters: &str, input: &str) -> usize {
    input.chars().filter(|&c| characters.contains(c)).count()
}

/// Returns all the characters in the input string that are also in the characters string.
pub fn get_matching_characters(characters: &str, input: &str, maximum_len: usize) -> String {
    input
        .chars()
        .filter(|&c| characters.contains(c))
        .take(maximum_len)
        .collect::<String>()
}

/// Models a sequence of characters in one or more forms as strings of equal length where each string represents one form
/// of characters in the sequence.
///
/// # Author
/// Middleware Services
#[derive(Debug, PartialEq, Eq)]
pub struct CharacterSequence {
    /// Character forms.
    forms: Vec<String>,
}

impl CharacterSequence {
    /// Creates a new instance from one or more sequences.
    ///
    /// # Arguments
    ///
    /// * `strings`: One or more characters strings, one for each form. At least one sequence MUST be defined. If
    ///              multiple sequences are defined, they MUST be of equal length.
    pub fn new(strings: Vec<String>) -> Result<Self, String> {
        if strings.is_empty() {
            Err("At least one sequence must be defined".to_string())
        } else if !strings.iter().all(|s| s.chars().count() == strings[0].chars().count()) {
            Err("Strings have unequal length".to_string())
        } else {
            Ok(CharacterSequence { forms: strings })
        }
    }

    /// Returns the array of strings that define character forms.
    pub fn get_forms(&self) -> &Vec<String> {
        &self.forms
    }

    /// Determines whether the character at the given index of the sequence matches the given value. Both original and
    /// variant forms are considered.
    ///
    /// # Arguments
    ///
    /// * `index`: Character sequence index.
    /// * `c`: Character to check for.
    ///
    /// # Returns
    ///
    /// True if sequence contains given character, false otherwise.
    pub fn matches(&self, index: usize, c: char) -> bool {
        self.forms.iter().any(|s| s.chars().nth(index).unwrap() == c)
    }

    /// Returns the length of character sequence.
    pub fn length(&self) -> usize {
        self.forms[0].chars().count()
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::character_sequence::CharacterSequence;

    #[test]
    fn test_no_sequences_failure() {
        let result = CharacterSequence::new(vec![]);
        let expected_err = Err("At least one sequence must be defined".to_string());
        assert_eq!(expected_err, result);
    }
    #[test]
    fn test_unequal_sequence_failure() {
        let result = CharacterSequence::new(vec!["12345".to_string(), "!@#$".to_string()]);
        let expected_err = Err("Strings have unequal length".to_string());
        assert_eq!(expected_err, result);
    }
    #[test]
    fn test_matches() {
        let sequence = CharacterSequence::new(vec![
            "12345".to_string(),
            "ABCDE".to_string(),
            "abcde".to_string(),
        ])
        .unwrap();
        assert!(sequence.matches(0, '1'));
        assert!(sequence.matches(0, 'A'));
        assert!(sequence.matches(0, 'a'));
        assert_eq!(false, sequence.matches(4, 'z'));
    }
}

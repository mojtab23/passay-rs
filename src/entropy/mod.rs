use crate::rule::character::CharacterRule;
use crate::rule::character_characteristics::CharacterCharacteristics;
use crate::rule::character_data::EnglishCharacterData;
use crate::rule::PasswordData;
use crate::rule::Rule;
use std::collections::HashSet;
use std::f64;

pub trait Entropy {
    /// Returns the estimated entropy bits of a password.
    fn estimate(&self) -> f64;
}

/// Entropy bits estimate defined in NIST SP-800-63-1 Randomly Selected Passwords.
/// see [http://csrc.nist.gov/publications/nistpubs/800-63-1/SP-800-63-1.pdf](PDF Publication)
/// A1. "Randomly Selected Passwords"
///
/// # Example
///
/// ```
///    use passay_rs::entropy::RandomPasswordEntropy;
///    use passay_rs::rule::Rule;
///    use passay_rs::rule::character_characteristics::CharacterCharacteristics;
///    use passay_rs::rule::character::CharacterRule;
///    use passay_rs::rule::character_data::EnglishCharacterData;
///    use passay_rs::rule::allowed_character::AllowedCharacter;
///    use passay_rs::rule::PasswordData;
///    use passay_rs::entropy::Entropy;
///
///    let allowed_rules = AllowedCharacter::from_chars("abcdefghijklmnopqrstuvwxyzL");
///    let ch_rules = vec![
///        CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
///        CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
///    ];
///    let char_rule = CharacterCharacteristics::with_rules_and_characteristics(ch_rules, 2).unwrap();
///
///    let rules:Vec<Box<dyn Rule>> = vec![Box::new(allowed_rules), Box::new(char_rule)];
///    let entropy = RandomPasswordEntropy::new(rules.as_slice(), &PasswordData::with_password("heLlo".to_string())).unwrap();
///    let ent = entropy.estimate();
///    assert_eq!(28.50219859070546, ent);
/// ```
pub struct RandomPasswordEntropy {
    alphabet_size: usize,
    password_size: usize,
}
impl RandomPasswordEntropy {
    pub fn new(
        rules: &[Box<dyn Rule>],
        password_data: &PasswordData,
    ) -> Result<Self, &'static str> {
        // TODO check password data origin
        let mut unique_chars = HashSet::<char>::new();

        for rule in rules {
            if let Some(ccc) = rule.as_has_characters() {
                unique_chars.extend(ccc.characters().chars())
            }
        }
        if unique_chars.is_empty() {
            return Err("Password rules must contain at least 1 unique character by CharacterRule definition");
        }
        Ok(RandomPasswordEntropy {
            alphabet_size: unique_chars.len(),
            password_size: password_data.password().len(),
        })
    }
}
impl Entropy for RandomPasswordEntropy {
    fn estimate(&self) -> f64 {
        let base = self.alphabet_size as f64;
        let exponent = self.password_size as f64;
        let power_result = base.powf(exponent);
        log2(power_result)
    }
}

fn log2(number: f64) -> f64 {
    number.ln() / f64::consts::LN_2
}

const FIRST_PHASE_LENGTH: usize = 1;
const SECOND_PHASE_LENGTH: usize = 8;
const THIRD_PHASE_LENGTH: usize = 20;
const FIRST_PHASE_BONUS: f64 = 4.0;
const SECOND_PHASE_BONUS: f64 = 2.0;
const THIRD_PHASE_BONUS: f64 = 1.5;

/// Array used for determining dictionary entropy "bonus" for calculating the Shannon entropy estimate.
const SHANNON_DICTIONARY_SIEVE: &[usize] =
    &[0, 0, 0, 4, 5, 6, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0];
/// Array used for determining composition "bonus" for calculating the Shannon entropy estimate.
const SHANNON_COMPOSITION_SIEVE: &[usize] = &[0, 0, 0, 2, 3, 3, 5, 6];

/// Returns the entropy bits of a user selected password. This estimate is based on a 94 Character Alphabet and is a
/// "ballpark" estimate based on Claude Shannon's observations.
/// See [http://csrc.nist.gov/publications/nistpubs/800-63-1/SP-800-63-1.pdf](PDF Publication)
/// A1. "User Selected Passwords"
///
/// # Example
///
/// ```
///    use passay_rs::entropy::ShannonEntropy;
///    use passay_rs::rule::Rule;
///    use passay_rs::rule::character_characteristics::CharacterCharacteristics;
///    use passay_rs::rule::character::CharacterRule;
///    use passay_rs::rule::character_data::EnglishCharacterData;
///    use passay_rs::rule::allowed_character::AllowedCharacter;
///    use passay_rs::rule::PasswordData;
///    use passay_rs::entropy::Entropy;
///
///    let allowed_rules = AllowedCharacter::from_chars("abcdefghijklmnopqrstuvwxyzL");
///    let ch_rules = vec![
///        CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
///        CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
///    ];
///    let char_rule = CharacterCharacteristics::with_rules_and_characteristics(ch_rules, 2).unwrap();
///
///    let rules:Vec<Box<dyn Rule>> = vec![Box::new(allowed_rules), Box::new(char_rule)];
///    let entropy = ShannonEntropy::from_rules(rules.as_slice(), &PasswordData::with_password("heLlo".to_string()));
///    let ent = entropy.estimate();
///    assert_eq!(12.0, ent);
/// ```
pub struct ShannonEntropy {
    /// Whether a dictionary was used to check the password.
    has_dictionary_check: bool,
    /// Whether at least 1 uppercase and special/symbol character is enforced.
    has_composition_check: bool,
    password_len: usize,
}
const COMPOSITION_CHARACTERISTICS_REQUIREMENT: usize = 4;

impl ShannonEntropy {
    pub fn new(has_dictionary_check: bool, password_data: &PasswordData) -> ShannonEntropy {
        // TODO check password data origin
        let has_composition_check = Self::has_composition(password_data);
        ShannonEntropy {
            has_dictionary_check,
            has_composition_check,
            password_len: password_data.password().len(),
        }
    }

    pub fn from_rules(rules: &[Box<dyn Rule>], password_data: &PasswordData) -> ShannonEntropy {
        let mut has_dict = false;
        for rule in rules {
            if let Some(dr) = rule.as_dictionary_rule() {
                has_dict = !dr.dictionary().is_empty();
                break;
            }
        }
        Self::new(has_dict, password_data)
    }
    fn has_composition(password_data: &PasswordData) -> bool {
        let crs = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 1).unwrap(),
        ];

        let composition_validator = CharacterCharacteristics::with_rules_and_characteristics(
            crs,
            COMPOSITION_CHARACTERISTICS_REQUIREMENT,
        )
        .unwrap();

        composition_validator.validate(password_data).valid()
    }
}

impl Entropy for ShannonEntropy {
    fn estimate(&self) -> f64 {
        let mut shannon_entropy = 0.0;
        if self.password_len > 0 {
            dbg!("first phase");
            shannon_entropy += FIRST_PHASE_BONUS;
            if self.password_len > SECOND_PHASE_LENGTH {
                shannon_entropy +=
                    (SECOND_PHASE_LENGTH - FIRST_PHASE_LENGTH) as f64 * SECOND_PHASE_BONUS;
                if self.password_len > THIRD_PHASE_LENGTH {
                    //4th phase bonus is 1 point, so (passwordSize - THIRD_PHASE_LENGTH) will suffice
                    shannon_entropy += (THIRD_PHASE_LENGTH - SECOND_PHASE_LENGTH) as f64
                        * THIRD_PHASE_BONUS
                        + (self.password_len - THIRD_PHASE_LENGTH) as f64;
                } else {
                    shannon_entropy +=
                        (self.password_len - SECOND_PHASE_LENGTH) as f64 * THIRD_PHASE_BONUS;
                }
            } else {
                dbg!("second phase else");
                shannon_entropy +=
                    (self.password_len - FIRST_PHASE_LENGTH) as f64 * SECOND_PHASE_BONUS;
            }
            if self.has_composition_check {
                dbg!("has_composition_check");

                let idx = if self.password_len > SHANNON_COMPOSITION_SIEVE.len() {
                    SHANNON_COMPOSITION_SIEVE.len() - 1
                } else {
                    self.password_len - 1
                };
                shannon_entropy += SHANNON_COMPOSITION_SIEVE[idx] as f64;
            }
            if self.has_dictionary_check {
                dbg!("has_dictionary_check");
                let idx = if self.password_len > SHANNON_DICTIONARY_SIEVE.len() {
                    SHANNON_DICTIONARY_SIEVE.len() - 1
                } else {
                    self.password_len - 1
                };

                shannon_entropy += SHANNON_DICTIONARY_SIEVE[idx] as f64;
            }
        }
        shannon_entropy
    }
}

#[cfg(test)]
mod tests {
    use crate::entropy::{Entropy, RandomPasswordEntropy, ShannonEntropy};
    use crate::rule::allowed_character::AllowedCharacter;
    use crate::rule::character::CharacterRule;
    use crate::rule::character_characteristics::CharacterCharacteristics;
    use crate::rule::character_data::EnglishCharacterData;
    use crate::rule::{PasswordData, Rule};

    // TODO need more tests for entropy
    #[test]
    fn test_random_entropy() {
        let entropy = RandomPasswordEntropy::new(
            create_rules().as_slice(),
            &PasswordData::with_password("heLlo".to_string()),
        )
        .unwrap();
        let ent = entropy.estimate();
        assert_eq!(28.50219859070546, ent);
    }

    #[test]
    fn test_shannon_entropy() {
        let entropy = ShannonEntropy::from_rules(
            create_rules().as_slice(),
            &PasswordData::with_password("heLlo".to_string()),
        );
        let ent = entropy.estimate();
        assert_eq!(12.0, ent);
    }

    fn create_rules() -> Vec<Box<dyn Rule>> {
        let allowed_rules = AllowedCharacter::from_chars("abcdefghijklmnopqrstuvwxyzL");
        let ch_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ];
        // there is a bug in java with invalid number of characteristics of 3
        let char_rule =
            CharacterCharacteristics::with_rules_and_characteristics(ch_rules, 2).unwrap();

        vec![Box::new(allowed_rules), Box::new(char_rule)]
    }
}

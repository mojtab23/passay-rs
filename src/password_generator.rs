use crate::rule::character::CharacterRule;

use rand::distr::Distribution;
use rand::distr::Uniform;
use rand::rngs::StdRng;
use rand::SeedableRng;

pub struct PasswordGenerator {
    random: StdRng,
}

impl PasswordGenerator {
    pub fn new() -> Self {
        Self {
            random: StdRng::from_os_rng(),
        }
    }

    pub fn generate_password(
        &mut self,
        len: usize,
        rules: &Vec<CharacterRule>,
    ) -> Result<String, String> {
        if len == 0 {
            return Err("length must be greater than 0".into());
        }
        let mut target = String::new();
        let mut all_chars = String::new();
        for rule in rules {
            target = self.fill_random_char(
                rule.valid_characters(),
                len.min(rule.num_characters()),
                target,
            )?;
            all_chars.push_str(&rule.valid_characters());
        }
        target = self.fill_random_char(&all_chars, len - target.chars().count(), target)?;
        Ok(target)
    }

    fn fill_random_char(
        &mut self,
        source: &str,
        size: usize,
        mut target: String,
    ) -> Result<String, String> {
        let result = Uniform::try_from(0..source.chars().count());
        let mut uni = match result {
            Ok(x) => x,
            Err(e) => {
                return Err(e.to_string());
            }
        };

        for _ in 0..size {
            let src_chars = source.chars().collect::<Vec<char>>();
            let index = uni.sample(&mut self.random);
            let char = src_chars[index];
            target.push(char);
        }
        Ok(target)
    }

    fn randomize(&mut self, str: String) -> Result<String, String> {
        let mut c: char;
        let mut n: usize;
        let mut chars: Vec<char> = str.chars().collect();
        let result = Uniform::try_from(0..chars.len());
        let mut uni = match result {
            Ok(x) => x,
            Err(e) => {
                return Err(e.to_string());
            }
        };

        for i in 0..chars.len() {
            n = uni.sample(&mut self.random);
            c = chars[n];
            chars[n] = chars[i];
            chars[i] = c;
        }
        Ok(chars.iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::password_generator::PasswordGenerator;
    use crate::rule::character::CharacterRule;
    use crate::rule::character_characteristics::CharacterCharacteristics;
    use crate::rule::character_data::EnglishCharacterData;
    use crate::rule::{PasswordData, Rule};
    use std::ops::Not;

    #[test]
    fn test_generator() {
        let passwords = random_passwords();
        for pass in passwords {
            let password_data = PasswordData::with_password(pass);
            assert!(gen_fail_rule().validate(&password_data).valid().not());
            assert!(gen_verify_rule().validate(&password_data).valid());
        }
    }

    #[test]
    fn test_buffer_overflow() {
        let output = PasswordGenerator::new()
            .generate_password(
                5,
                &vec![CharacterRule::new(Box::new(EnglishCharacterData::Digit), 10).unwrap()],
            )
            .unwrap();
        let output = PasswordGenerator::new()
            .generate_password(
                10,
                &vec![CharacterRule::new(Box::new(EnglishCharacterData::Digit), 5).unwrap()],
            )
            .unwrap();
        let output = PasswordGenerator::new()
            .generate_password(
                10,
                &vec![CharacterRule::new(Box::new(EnglishCharacterData::Digit), 10).unwrap()],
            )
            .unwrap();
    }
    fn random_passwords() -> Vec<String> {
        let mut passwords = Vec::with_capacity(100);
        const LEN: usize = 10;

        let mut password_generator = PasswordGenerator::new();

        let rule = gen_rule();
        for i in 0..100 {
            let password = password_generator.generate_password(LEN, &rule).unwrap();
            dbg!(password.chars().count());
            debug_assert!(password.chars().count() >= LEN);
            passwords.push(password);
        }
        passwords
    }
    fn gen_rule() -> Vec<CharacterRule> {
        vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 2).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 2).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 1).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 1).unwrap(),
        ]
    }
    fn gen_verify_rule() -> CharacterCharacteristics {
        CharacterCharacteristics::with_rules_and_characteristics(gen_rule(), 3).unwrap()
    }
    fn gen_fail_rule() -> CharacterCharacteristics {
        let char_rules = vec![
            CharacterRule::new(Box::new(EnglishCharacterData::Digit), 3).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::Special), 3).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::UpperCase), 3).unwrap(),
            CharacterRule::new(Box::new(EnglishCharacterData::LowerCase), 3).unwrap(),
        ];

        CharacterCharacteristics::with_rules_and_characteristics(char_rules, 4).unwrap()
    }
}

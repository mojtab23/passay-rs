use crate::rule::character_sequence::CharacterSequence;

/// Container for one or more CharacterSequence.
///
/// # Author
/// Middleware Services
pub trait SequenceData {
    /// Return the error code used for message resolution.
    ///
    /// # Returns
    /// error code
    fn error_code(&self) -> &str;

    /// # Returns
    /// one or more illegal character sequences.
    fn get_sequences(&self) -> Vec<CharacterSequence>;
}

/// English character sequences.
///
/// # Author
/// Middleware Services
#[derive(Debug, PartialEq, Eq)]
pub enum EnglishSequenceData {
    Alphabetical,
    Numerical,
    USQwerty,
}

impl SequenceData for EnglishSequenceData {
    fn error_code(&self) -> &str {
        match self {
            EnglishSequenceData::Alphabetical => "ILLEGAL_ALPHABETICAL_SEQUENCE",
            EnglishSequenceData::Numerical => "ILLEGAL_NUMERICAL_SEQUENCE",
            EnglishSequenceData::USQwerty => "ILLEGAL_QWERTY_SEQUENCE",
        }
    }

    fn get_sequences(&self) -> Vec<CharacterSequence> {
        match self {
            EnglishSequenceData::Alphabetical =>
                vec![CharacterSequence::new(vec![
                    "abcdefghijklmnopqrstuvwxyz".to_string(),
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
                ])
                    .unwrap()],
            EnglishSequenceData::Numerical =>
                vec![
                    CharacterSequence::new(vec!["0123456789".to_string()]).unwrap(),
                ],
            EnglishSequenceData::USQwerty =>
                vec![
                    CharacterSequence::new(vec![
                        "`1234567890-=".to_string(),
                        "~!@#$%^&*()_+".to_string(),
                        "\u{0}\u{a1}\u{2122}\u{a3}\u{a2}\u{221e}\u{a7}\u{b6}\u{2022}\u{aa}\u{ba}\u{2013}\u{2260}".to_string(),
                        "\u{60}\u{2044}\u{20ac}\u{2039}\u{203a}\u{fb01}\u{fb02}\u{2021}\u{b0}\u{b7}\u{201a}\u{2014}\u{b1}".to_string()
                    ])
                        .unwrap(),
                    CharacterSequence::new(vec![
                        "qwertyuiop[]\\".to_string(),
                        "QWERTYUIOP{}|".to_string(),
                        "\u{153}\u{2211}\u{0}\u{ae}\u{2020}\u{a5}\u{0}\u{0}\u{f8}\u{3c0}\u{201c}\u{2018}\u{ab}".to_string(),
                        "\u{152}\u{201e}\u{b4}\u{2030}\u{2c7}\u{c1}\u{a8}\u{2c6}\u{d8}\u{220f}\u{201d}\u{2019}\u{bb}".to_string()
                    ])
                        .unwrap(),
                    CharacterSequence::new(vec![
                        "asdfghjkl;'".to_string(),
                        "ASDFGHJKL:\"".to_string(),
                        "\u{e5}\u{df}\u{2202}\u{192}\u{a9}\u{2d9}\u{2206}\u{2da}\u{ac}\u{2026}\u{e6}".to_string(),
                        "\u{c5}\u{cd}\u{ce}\u{cf}\u{2dd}\u{d3}\u{d4}\u{f8ff}\u{d2}\u{da}\u{c6}".to_string(),
                    ])
                        .unwrap(),
                    CharacterSequence::new(vec![
                        "zxcvbnm,./".to_string(),
                        "ZXCVBNM<>?".to_string(),
                        "\u{39}\u{2248}\u{e7}\u{221a}\u{222b}\u{0}\u{b5}\u{2264}\u{2265}\u{f7}".to_string(),
                        "\u{b8}\u{2db}\u{c7}\u{25ca}\u{131}\u{2dc}\u{c2}\u{af}\u{2d8}\u{bf}".to_string(),
                    ])
                        .unwrap(),
                ],
        }
    }
}

/// Polish character sequences.
pub enum PolishSequenceData {
    Alphabetical,
}

impl SequenceData for PolishSequenceData {
    fn error_code(&self) -> &str {
        match self {
            PolishSequenceData::Alphabetical => "ILLEGAL_ALPHABETICAL_SEQUENCE",
        }
    }

    fn get_sequences(&self) -> Vec<CharacterSequence> {
        match self {
            PolishSequenceData::Alphabetical => vec![CharacterSequence::new(vec![
                "aąbcćdeęfghijklmnoópqrsśtuwxyzźż".to_string(),
                "AĄBCĆDEĘFGHIJKLMNOÓPQRSŚTUWXYZŹŻ".to_string(),
            ])
            .unwrap()],
        }
    }
}

pub enum GermanSequenceData {
    Alphabetical,
    DEQwertz,
}

impl SequenceData for GermanSequenceData {
    fn error_code(&self) -> &str {
        match self {
            GermanSequenceData::Alphabetical => "ILLEGAL_ALPHABETICAL_SEQUENCE",
            GermanSequenceData::DEQwertz => "ILLEGAL_QWERTY_SEQUENCE",
        }
    }

    fn get_sequences(&self) -> Vec<CharacterSequence> {
        match self {
            GermanSequenceData::Alphabetical => vec![CharacterSequence::new(vec![
                "abcdefghijklmnopqrstuvwxyzäöüß".to_string(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÜẞ".to_string(),
            ])
            .unwrap()],
            GermanSequenceData::DEQwertz => vec![
                CharacterSequence::new(vec![
                    "^1234567890\\´".to_string(),
                    "°!\"§$%&/()=?`".to_string(),
                    // "\u{0000}\u{0000}²³\u{0000}\u{0000}\u{0000}{[]}\\\u{0000}".to_string(),
                ])
                .unwrap(),
                CharacterSequence::new(vec![
                    "qwertzuiopü+".to_string(),
                    "QWERTZUIOPÜ*".to_string(),
                    // "@\u{0000}€\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}~".to_string(),
                ])
                .unwrap(),
                CharacterSequence::new(vec![
                    "asdfghjklöä#".to_string(),
                    "ASDFGHJKLÖÄ'".to_string(),
                    // "\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}".to_string(),
                ])
                .unwrap(),
                CharacterSequence::new(vec![
                    "<yxcvbnm,.-".to_string(),
                    ">YXCVBNM;:_".to_string(),
                    // "|\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}\u{0000}µ\u{0000}\u{0000}\u{0000}".to_string(),
                ])
                .unwrap(),
            ],
        }
    }
}

pub enum CzechSequenceData {
    Alphabetical,
}

impl SequenceData for CzechSequenceData {
    fn error_code(&self) -> &str {
        match self {
            CzechSequenceData::Alphabetical => "ILLEGAL_ALPHABETICAL_SEQUENCE",
        }
    }

    fn get_sequences(&self) -> Vec<CharacterSequence> {
        match self {
            CzechSequenceData::Alphabetical => vec![CharacterSequence::new(vec![
                "aábcčdďeěéfghiíjklmnňoópqrřsštťuúůvwxyýzž".to_string(),
                "AÁBCČDĎEĚÉFGHIÍJKLMNŇOÓPQRŘSŠTŤUÚŮVWXYÝZŽ".to_string(),
            ])
            .unwrap()],
        }
    }
}

pub enum CyrillicSequenceData {
    Alphabetical,
}

impl SequenceData for CyrillicSequenceData {
    fn error_code(&self) -> &str {
        match self {
            CyrillicSequenceData::Alphabetical => "ILLEGAL_ALPHABETICAL_SEQUENCE",
        }
    }

    fn get_sequences(&self) -> Vec<CharacterSequence> {
        match self {
            CyrillicSequenceData::Alphabetical => vec![CharacterSequence::new(vec![
                "абвгдеёжзийклмнопрстуфхцчшщъыьэюяіѣѳѵ".to_string(),
                "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯІѢѲѴ".to_string(),
            ])
            .unwrap()],
        }
    }
}

use crate::rule::rule_result::CountCategory;

/// Input data used by [CharacterRule](crate::rule::character::CharacterRule)
pub trait CharacterData {
    fn characters(&self) -> &str;
    fn error_code(&self) -> &str;

    fn count_category(&self) -> Option<CountCategory>;
}

/// English language character data.
pub enum EnglishCharacterData {
    LowerCase,
    UpperCase,
    Digit,
    Alphabetical,
    Special,
}
macro_rules! upper {
    () => {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };
}
macro_rules! lower {
    () => {
        "abcdefghijklmnopqrstuvwxyz"
    };
}
macro_rules! alphabetical {
    () => {
        concat!(upper!(), lower!())
    };
}
impl CharacterData for EnglishCharacterData {
    fn characters(&self) -> &str {
        match self {
            EnglishCharacterData::LowerCase => lower!(),
            EnglishCharacterData::UpperCase => upper!(),
            EnglishCharacterData::Digit => "0123456789",
            EnglishCharacterData::Alphabetical => alphabetical!(),
            EnglishCharacterData::Special => {
                "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\
                \u{00a1}\u{00a2}\u{00a3}\u{00a4}\u{00a5}\u{00a6}\u{00a7}\u{00a8}\u{00a9}\u{00aa}\u{00ab}\u{00ac}\u{00ad}\u{00ae}\u{00af}\
                \u{00b0}\u{00b1}\u{00b2}\u{00b3}\u{00b4}\u{00b5}\u{00b6}\u{00b7}\u{00b8}\u{00b9}\u{00ba}\u{00bb}\u{00bc}\u{00bd}\u{00be}\u{00bf}\
                \u{00d7}\u{00f7}\
                \u{2013}\u{2014}\u{2015}\u{2017}\u{2018}\u{2019}\u{201a}\u{201b}\u{201c}\u{201d}\u{201e}\u{2020}\u{2021}\u{2022}\u{2026}\u{2030}\u{2032}\u{2033}\
                \u{2039}\u{203a}\u{203c}\u{203e}\u{2044}\u{204a}\
                \u{20a0}\u{20a1}\u{20a2}\u{20a3}\u{20a4}\u{20a5}\u{20a6}\u{20a7}\u{20a8}\u{20a9}\u{20aa}\u{20ab}\u{20ac}\u{20ad}\u{20ae}\u{20af}\
                \u{20b0}\u{20b1}\u{20b2}\u{20b3}\u{20b4}\u{20b5}\u{20b6}\u{20b7}\u{20b8}\u{20b9}\u{20ba}\u{20bb}\u{20bc}\u{20bd}\u{20be}"
            }
        }
    }

    fn error_code(&self) -> &str {
        match self {
            EnglishCharacterData::LowerCase => "INSUFFICIENT_LOWERCASE",
            EnglishCharacterData::UpperCase => "INSUFFICIENT_UPPERCASE",
            EnglishCharacterData::Digit => "INSUFFICIENT_DIGIT",
            EnglishCharacterData::Alphabetical => "INSUFFICIENT_ALPHABETICAL",
            EnglishCharacterData::Special => "INSUFFICIENT_SPECIAL",
        }
    }
    fn count_category(&self) -> Option<CountCategory> {
        match self {
            EnglishCharacterData::LowerCase => Some(CountCategory::LowerCase),
            EnglishCharacterData::UpperCase => Some(CountCategory::UpperCase),
            EnglishCharacterData::Digit => Some(CountCategory::Digit),
            EnglishCharacterData::Alphabetical => None,
            EnglishCharacterData::Special => Some(CountCategory::Special),
        }
    }
}

/// Cyrillic character data.
pub enum CyrillicCharacterData {
    LowerCase,
    UpperCase,
}
impl CharacterData for CyrillicCharacterData {
    fn characters(&self) -> &str {
        match self {
            CyrillicCharacterData::LowerCase => "абвгдеёжзийклмнопрстуфхцчшщъыьэюяіѣѳѵ",
            CyrillicCharacterData::UpperCase => "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯІѢѲѴ",
        }
    }

    fn error_code(&self) -> &str {
        match self {
            CyrillicCharacterData::LowerCase => "INSUFFICIENT_LOWERCASE",
            CyrillicCharacterData::UpperCase => "INSUFFICIENT_UPPERCASE",
        }
    }

    fn count_category(&self) -> Option<CountCategory> {
        match self {
            CyrillicCharacterData::LowerCase => Some(CountCategory::LowerCase),
            CyrillicCharacterData::UpperCase => Some(CountCategory::UpperCase),
        }
    }
}

/// Modern Cyrillic character data.
pub enum CyrillicModernCharacterData {
    LowerCase,
    UpperCase,
}
impl CharacterData for CyrillicModernCharacterData {
    fn characters(&self) -> &str {
        match self {
            CyrillicModernCharacterData::LowerCase => "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
            CyrillicModernCharacterData::UpperCase => "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
        }
    }

    fn error_code(&self) -> &str {
        match self {
            CyrillicModernCharacterData::LowerCase => "INSUFFICIENT_LOWERCASE",
            CyrillicModernCharacterData::UpperCase => "INSUFFICIENT_UPPERCASE",
        }
    }
    fn count_category(&self) -> Option<CountCategory> {
        match self {
            CyrillicModernCharacterData::LowerCase => Some(CountCategory::LowerCase),
            CyrillicModernCharacterData::UpperCase => Some(CountCategory::UpperCase),
        }
    }
}

/// Czech character data.
pub enum CzechCharacterData {
    LowerCase,
    UpperCase,
}

impl CharacterData for CzechCharacterData {
    fn characters(&self) -> &str {
        match self {
            CzechCharacterData::LowerCase => "aábcčdďeěéfghiíjklmnňoópqrřsštťuúůvwxyýzž",
            CzechCharacterData::UpperCase => "AÁBCČDĎEĚÉFGHIÍJKLMNŇOÓPQRŘSŠTŤUÚŮVWXYÝZŽ",
        }
    }

    fn error_code(&self) -> &str {
        match self {
            CzechCharacterData::LowerCase => "INSUFFICIENT_LOWERCASE",
            CzechCharacterData::UpperCase => "INSUFFICIENT_UPPERCASE",
        }
    }
    fn count_category(&self) -> Option<CountCategory> {
        match self {
            CzechCharacterData::LowerCase => Some(CountCategory::LowerCase),
            CzechCharacterData::UpperCase => Some(CountCategory::UpperCase),
        }
    }
}

/// German character data.
pub enum GermanCharacterData {
    LowerCase,
    UpperCase,
}

impl CharacterData for GermanCharacterData {
    fn characters(&self) -> &str {
        match self {
            GermanCharacterData::LowerCase => "abcdefghijklmnopqrstuvwxyzäöüß",
            GermanCharacterData::UpperCase => "ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÜẞ",
        }
    }

    fn error_code(&self) -> &str {
        match self {
            GermanCharacterData::LowerCase => "INSUFFICIENT_LOWERCASE",
            GermanCharacterData::UpperCase => "INSUFFICIENT_UPPERCASE",
        }
    }
    fn count_category(&self) -> Option<CountCategory> {
        match self {
            GermanCharacterData::LowerCase => Some(CountCategory::LowerCase),
            GermanCharacterData::UpperCase => Some(CountCategory::UpperCase),
        }
    }
}

/// Polish character data.
pub enum PolishCharacterData {
    LowerCase,
    UpperCase,
}

impl CharacterData for PolishCharacterData {
    fn characters(&self) -> &str {
        match self {
            PolishCharacterData::LowerCase => "aąbcćdeęfghijklłmnńoópqrsśtuvwxyzźż",
            PolishCharacterData::UpperCase => "AĄBCĆDEĘFGHIJKLŁMNŃOÓPQRSŚTUVWXYZŹŻ",
        }
    }

    fn error_code(&self) -> &str {
        match self {
            PolishCharacterData::LowerCase => "INSUFFICIENT_LOWERCASE",
            PolishCharacterData::UpperCase => "INSUFFICIENT_UPPERCASE",
        }
    }
    fn count_category(&self) -> Option<CountCategory> {
        match self {
            PolishCharacterData::LowerCase => Some(CountCategory::LowerCase),
            PolishCharacterData::UpperCase => Some(CountCategory::UpperCase),
        }
    }
}

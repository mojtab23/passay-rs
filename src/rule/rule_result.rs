use std::collections::HashMap;
use std::fmt::{Display, Formatter};

pub struct RuleResult {
    valid: bool,
    details: Vec<RuleResultDetail>,
    metadata: RuleResultMetadata,
}

impl RuleResult {
    pub fn new(valid: bool) -> Self {
        Self {
            valid,
            details: vec![],
            metadata: RuleResultMetadata::default(),
        }
    }

    pub fn add_error(&mut self, code: &str, params: Option<HashMap<String, String>>) {
        self.valid = false;
        self.details
            .push(RuleResultDetail::new(vec![code.to_string()], params))
    }

    pub fn metadata(&self) -> &RuleResultMetadata {
        &self.metadata
    }
    pub fn set_metadata(&mut self, metadata: RuleResultMetadata) {
        self.metadata = metadata;
    }

    pub fn valid(&self) -> bool {
        self.valid
    }
}

pub struct RuleResultDetail {
    error_codes: Vec<String>,
    parameters: HashMap<String, String>,
}

impl RuleResultDetail {
    fn new(error_codes: Vec<String>, parameters: Option<HashMap<String, String>>) -> Self {
        if error_codes.is_empty() {
            panic!("Must specify at least one error code.")
        }
        for error_code in error_codes.iter() {
            if error_code.is_empty() {
                panic!("Code cannot be null or empty.")
            }
        }

        let parameters = parameters.unwrap_or(HashMap::new());
        Self {
            error_codes,
            parameters,
        }
    }
}

impl Display for RuleResultDetail {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}:{:?}", self.error_codes, self.parameters)
    }
}

pub struct RuleResultMetadata {
    counts: HashMap<CountCategory, usize>,
}

impl RuleResultMetadata {
    pub fn new(category: CountCategory, value: usize) -> Self {
        let mut counts = HashMap::new();
        counts.insert(category, value);
        Self { counts }
    }
    pub fn get_count(&self, category: &CountCategory) -> Option<&usize> {
        self.counts.get(category)
    }
}

impl Default for RuleResultMetadata {
    fn default() -> Self {
        RuleResultMetadata {
            counts: HashMap::default(),
        }
    }
}
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum CountCategory {
    /// password length.
    Length,

    /// lowercase characters.
    LowerCase,

    /// uppercase characters.
    UpperCase,

    /// digit characters.
    Digit,

    /// special characters.
    Special,

    /// whitespace characters.
    Whitespace,

    /// allowed characters.
    Allowed,

    /// illegal characters.
    Illegal,
}

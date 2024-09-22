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

    pub fn add_error_with_codes(
        &mut self,
        codes: &[String],
        params: Option<HashMap<String, String>>,
    ) {
        self.valid = false;
        let error_codes = codes.to_vec();
        self.details
            .push(RuleResultDetail::new(error_codes, params))
    }

    pub fn metadata(&self) -> &RuleResultMetadata {
        &self.metadata
    }
    pub fn metadata_mut(&mut self) -> &mut RuleResultMetadata {
        &mut self.metadata
    }
    pub fn set_metadata(&mut self, metadata: RuleResultMetadata) {
        self.metadata = metadata;
    }

    pub fn valid(&self) -> bool {
        self.valid
    }

    pub fn set_valid(&mut self, valid: bool) {
        self.valid = valid;
    }

    pub fn details(&self) -> &Vec<RuleResultDetail> {
        &self.details
    }
    pub fn details_mut(&mut self) -> &mut Vec<RuleResultDetail> {
        &mut self.details
    }
}

impl Default for RuleResult {
    fn default() -> Self {
        RuleResult::new(true)
    }
}

#[derive(Debug)]
pub struct RuleResultDetail {
    error_codes: Vec<String>,
    parameters: HashMap<String, String>,
}

impl RuleResultDetail {
    pub fn new(error_codes: Vec<String>, parameters: Option<HashMap<String, String>>) -> Self {
        if error_codes.is_empty() {
            panic!("Must specify at least one error code.")
        }
        for error_code in error_codes.iter() {
            if error_code.is_empty() {
                panic!("Code cannot be null or empty.")
            }
        }

        let parameters = parameters.unwrap_or_default();
        Self {
            error_codes,
            parameters,
        }
    }
    /// Returns the least-specific error code.
    pub fn error_code(&self) -> &str {
        &self.error_codes[self.error_codes.len() - 1]
    }

    /// Returns an array of error codes as provided at creation time.
    pub fn error_codes(&self) -> &[String] {
        self.error_codes.as_slice()
    }
}

impl Display for RuleResultDetail {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}:{:?}", self.error_codes, self.parameters)
    }
}

#[derive(Default)]
pub struct RuleResultMetadata {
    counts: HashMap<CountCategory, usize>,
}

impl RuleResultMetadata {
    pub fn new(category: CountCategory, value: usize) -> Self {
        let mut counts = HashMap::new();
        counts.insert(category, value);
        Self { counts }
    }
    pub fn get_count(&self, category: CountCategory) -> Option<usize> {
        self.counts.get(&category).copied()
    }

    pub fn merge(&mut self, other: &RuleResultMetadata) {
        self.counts.extend(other.counts.clone());
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
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

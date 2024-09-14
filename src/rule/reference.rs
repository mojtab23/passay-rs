use std::any::Any;
use std::fmt::Debug;

pub trait Reference: Debug {
    fn password(&self) -> &str;
    fn salt(&self) -> &Option<Box<dyn Salt>> {
        &None
    }

    fn as_any(&self) -> &dyn Any;
}

#[derive(Debug)]
pub struct VoidReference;

impl Reference for VoidReference {
    fn password(&self) -> &str {
        ""
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait Salt {
    fn apply_to(&self, password: String) -> String;
}

pub struct PrefixSalt {
    salt: String,
}

impl Salt for PrefixSalt {
    fn apply_to(&self, password: String) -> String {
        let mut s = self.salt.to_owned();
        s.push_str(&password);
        s
    }
}

pub struct SuffixSalt {
    salt: String,
}

impl Salt for SuffixSalt {
    fn apply_to(&self, mut password: String) -> String {
        password.push_str(&self.salt);
        password
    }
}

pub struct NoSalt;

impl Salt for NoSalt {
    fn apply_to(&self, password: String) -> String {
        password
    }
}

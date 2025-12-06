use std::any::Any;
use std::fmt::Debug;

pub trait Reference: Debug + Any {
    fn password(&self) -> &str;
    fn salt(&self) -> &Option<Salt>;

    fn as_any(&self) -> &dyn Any;
}

pub enum Salt {
    Prefix(String),
    Suffix(String),
}

impl Salt {
    pub fn prefix(s: String) -> Salt {
        Salt::Prefix(s)
    }
    pub fn suffix(s: String) -> Salt {
        Salt::Suffix(s)
    }
    pub fn apply_to(&self, password: String) -> String {
        match self {
            Salt::Prefix(s) => {
                let mut s = s.to_owned();
                s.push_str(&password);
                s
            }
            Salt::Suffix(s) => {
                let mut pass = password.to_owned();
                pass.push_str(s);
                pass
            }
        }
    }
}

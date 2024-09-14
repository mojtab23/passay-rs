use crate::rule::character_sequence::CharacterSequence;
use crate::rule::rule_result::RuleResult;
use crate::rule::sequence_data::SequenceData;
use crate::rule::{PasswordData, Rule};
use std::collections::HashMap;

pub const DEFAULT_SEQUENCE_LENGTH: usize = 5;
pub struct IllegalSequenceRule<S>
where
    S: SequenceData,
{
    sequence_data: S,
    length: usize,
    wrap: bool,
    report_all: bool,
}

impl<S: SequenceData> IllegalSequenceRule<S> {
    pub fn new(sequence_data: S, length: usize, wrap: bool, report_all: bool) -> Self {
        Self {
            sequence_data,
            length,
            wrap,
            report_all,
        }
    }
    pub fn with_sequence_data(sequence_data: S) -> Self {
        Self::new(sequence_data, DEFAULT_SEQUENCE_LENGTH, false, true)
    }
    pub fn with_warp(sequence_data: S, length: usize, wrap: bool) -> Self {
        Self::new(sequence_data, length, wrap, true)
    }

    fn add_error(&self, result: &mut RuleResult, match_str: &str) {
        if self.report_all || result.details().is_empty() {
            // let mut m = LinkedHashMap::new();
            let mut map = HashMap::new();

            map.insert("sequence".to_string(), match_str.to_string());
            result.add_error(self.sequence_data.get_error_code(), Some(map));
        }
    }
}
fn index_of(sequence: &CharacterSequence, c: char) -> isize {
    for i in 0..sequence.length() {
        if sequence.matches(i, c) {
            return i as isize;
        }
    }
    -1
}
impl<S: SequenceData> Rule for IllegalSequenceRule<S> {
    fn validate(&self, password_data: &PasswordData) -> RuleResult {
        let mut result = RuleResult::default();
        let password = format!("{}{}", password_data.password(), '\u{ffff}');
        let mut match_builder = String::with_capacity(password.len());
        for cs in self.sequence_data.get_sequences() {
            let cs_length: isize = cs.length() as isize;
            let mut direction = 0;
            let mut prev_position = -1;
            for (_i, c) in password.chars().enumerate() {
                let position = index_of(&cs, c);
                // set diff to +1 for increase in sequence, -1 for decrease, anything else for neither
                let mut diff = if position < 0 || prev_position < 0 {
                    0
                } else {
                    position - prev_position
                };
                if self.wrap && (diff == cs_length - 1 || diff == 1 - cs_length) {
                    diff -= diff.signum() * cs_length;
                }
                // if we have a sequence and reached its end, add it to result
                if diff != direction && match_builder.chars().count() >= self.length {
                    // result.add_error(match_builder.clone());
                    self.add_error(&mut result, &match_builder)
                }
                // update the current potential sequence
                if diff == 1 || diff == -1 {
                    if diff != direction {
                        match_builder = match_builder.chars().last().unwrap().to_string();
                        direction = diff;
                    }
                } else {
                    match_builder.clear();
                    direction = 0;
                }
                match_builder.push(c);
                prev_position = position;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::test::{check_messages, check_passwords, RulePasswordTestItem};
    use crate::{
        rule::illegal_sequence_rule::IllegalSequenceRule,
        rule::password_validator::PasswordValidator,
        rule::sequence_data::{
            CyrillicSequenceData, CzechSequenceData, EnglishSequenceData, GermanSequenceData,
            PolishSequenceData, SequenceData,
        },
        rule::PasswordData,
    };

    #[test]
    fn test_passwords() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            /* QWERTY SEQUENCE */
            // Test valid password
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::USQwerty,
                )),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // Has qwerty sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("pqwerty#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has qwerty sequence at beginning
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("qwerty#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has qwerty sequence at end
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("ppqwerty".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has qwerty sequence in entirety
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("qwerty".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has two qwerty sequences
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("pqwerty#n65tyuiop".to_string()),
                vec![
                    EnglishSequenceData::USQwerty.get_error_code(),
                    EnglishSequenceData::USQwerty.get_error_code(),
                ],
            ),
            // Has two joined qwerty sequences
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("qwertytrewq".to_string()),
                vec![
                    EnglishSequenceData::USQwerty.get_error_code(),
                    EnglishSequenceData::USQwerty.get_error_code(),
                ],
            ),
            // Has two joined qwerty sequences with padding
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("pqwertytrewqp".to_string()),
                vec![
                    EnglishSequenceData::USQwerty.get_error_code(),
                    EnglishSequenceData::USQwerty.get_error_code(),
                ],
            ),
            // Has wrapping qwerty sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::USQwerty,
                )),
                PasswordData::with_password("pkl;'a#n65".to_string()),
                vec![],
            ),
            // Has wrapping qwerty sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    8,
                    true,
                )),
                PasswordData::with_password("piop{}|qw#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has backward qwerty sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    4,
                    false,
                )),
                PasswordData::with_password("p7^54#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has backward wrapping qwerty sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    8,
                    false,
                )),
                PasswordData::with_password("phgfdsa\";#n65".to_string()),
                vec![],
            ),
            // Has backward wrapping qwerty sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    true,
                )),
                PasswordData::with_password("p@1`+_0#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                )),
                PasswordData::with_password("pQ∑eR†y#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has wrapping alt qwerty sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::USQwerty,
                )),
                PasswordData::with_password("pK¬;æA#n65".to_string()),
                vec![],
            ),
            // Has wrapping qwerty sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    8,
                    true,
                )),
                PasswordData::with_password("pIøp“}|œW#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has backwards alt qwerty sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    4,
                    false,
                )),
                PasswordData::with_password("p7§5›#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // Has backward alt wrapping qwerty sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    8,
                    false,
                )),
                PasswordData::with_password("ph©fÎßa\"…#n65".to_string()),
                vec![],
            ),
            // Has backward alt wrapping qwerty sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::USQwerty,
                    6,
                    true,
                )),
                PasswordData::with_password("p@1~≠_º#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // report single error
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::new(
                    EnglishSequenceData::USQwerty,
                    6,
                    false,
                    false,
                )),
                PasswordData::with_password("pqwertyui#n65".to_string()),
                vec![EnglishSequenceData::USQwerty.get_error_code()],
            ),
            // German QWERTZ SEQUENCE
            // Test valid password
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    GermanSequenceData::DEQwertz,
                )),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // Has one 6 character qwertz sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    GermanSequenceData::DEQwertz,
                    6,
                    false,
                )),
                PasswordData::with_password("pqwertz#n65".to_string()),
                vec![GermanSequenceData::Alphabetical.get_error_code()],
            ),
            // Has two 5 character qwertz sequences
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    GermanSequenceData::DEQwertz,
                    5,
                    false,
                )),
                PasswordData::with_password("wertz#~yxcvb".to_string()),
                vec![
                    GermanSequenceData::Alphabetical.get_error_code(),
                    GermanSequenceData::Alphabetical.get_error_code(),
                ],
            ),
            // Has one 4 character backward qwertz sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    GermanSequenceData::DEQwertz,
                    4,
                    false,
                )),
                PasswordData::with_password("1xäölk2y".to_string()),
                vec![GermanSequenceData::Alphabetical.get_error_code()],
            ),
            /* ALPHABETICAL SEQUENCE */
            // Test valid password
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::Alphabetical,
                )),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // Has alphabetical sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    7,
                    false,
                )),
                PasswordData::with_password("phijklmn#n65".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has wrapping alphabetical sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    4,
                    false,
                )),
                PasswordData::with_password("pXyza#n65".to_string()),
                vec![],
            ),
            // Has wrapping alphabetical sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    4,
                    true,
                )),
                PasswordData::with_password("pxyzA#n65".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has backward alphabetical sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::Alphabetical,
                )),
                PasswordData::with_password("ptSrqp#n65".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has backward wrapping alphabetical sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    8,
                    false,
                )),
                PasswordData::with_password("pcBazyXwv#n65".to_string()),
                vec![],
            ),
            // Has backward wrapping alphabetical sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    8,
                    true,
                )),
                PasswordData::with_password("pcbazyxwv#n65".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has forward alphabetical sequence that ends with 'y'
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    false,
                )),
                PasswordData::with_password("wxy".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has forward alphabetical sequence that ends with 'z'
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    false,
                )),
                PasswordData::with_password("xyz".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has forward alphabetical sequence that ends with 'a' with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    false,
                )),
                PasswordData::with_password("yza".to_string()),
                vec![],
            ),
            // Has forward alphabetical sequence that ends with 'a' with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    true,
                )),
                PasswordData::with_password("yza".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has backward alphabetical sequence that ends with 'b'
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    false,
                )),
                PasswordData::with_password("dcb".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has backward alphabetical sequence that ends with 'a'
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    false,
                )),
                PasswordData::with_password("cba".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // Has backward alphabetical sequence that ends with 'z' with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    false,
                )),
                PasswordData::with_password("baz".to_string()),
                vec![],
            ),
            // Has backward alphabetical sequence that ends with 'z' with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Alphabetical,
                    3,
                    true,
                )),
                PasswordData::with_password("baz".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // report single error
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::new(
                    EnglishSequenceData::Alphabetical,
                    5,
                    false,
                    false,
                )),
                PasswordData::with_password("phijklmn#n65".to_string()),
                vec![EnglishSequenceData::Alphabetical.get_error_code()],
            ),
            // NUMERICAL SEQUENCE
            // Test valid password
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::Numerical,
                )),
                PasswordData::with_password("p4zRcv8#n65".to_string()),
                vec![],
            ),
            // Has numerical sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Numerical,
                    4,
                    false,
                )),
                PasswordData::with_password("p3456#n65".to_string()),
                vec![EnglishSequenceData::Numerical.get_error_code()],
            ),
            // Has wrapping numerical sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Numerical,
                    7,
                    false,
                )),
                PasswordData::with_password("p4zRcv2#n8901234".to_string()),
                vec![],
            ),
            // Has wrapping numerical sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Numerical,
                    7,
                    true,
                )),
                PasswordData::with_password("p4zRcv2#n8901234".to_string()),
                vec![EnglishSequenceData::Numerical.get_error_code()],
            ),
            // Has backward numerical sequence
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::Numerical,
                )),
                PasswordData::with_password("p54321#n65".to_string()),
                vec![EnglishSequenceData::Numerical.get_error_code()],
            ),
            // Has backward wrapping numerical sequence with wrap=false
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Numerical,
                    5,
                    false,
                )),
                PasswordData::with_password("p987#n32109".to_string()),
                vec![],
            ),
            // Has backward wrapping numerical sequence with wrap=true
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Numerical,
                    8,
                    true,
                )),
                PasswordData::with_password("p54321098#n65".to_string()),
                vec![EnglishSequenceData::Numerical.get_error_code()],
            ),
            // Issue 135 original java repo
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_warp(
                    EnglishSequenceData::Numerical,
                    5,
                    true,
                )),
                PasswordData::with_password("1234567".to_string()),
                vec![EnglishSequenceData::Numerical.get_error_code()],
            ),
            // report single error
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::new(
                    EnglishSequenceData::Numerical,
                    5,
                    true,
                    false,
                )),
                PasswordData::with_password("1234567".to_string()),
                vec![EnglishSequenceData::Numerical.get_error_code()],
            ),
            // Polish and English
            RulePasswordTestItem(
                Box::new(PasswordValidator::new(vec![
                    Box::new(IllegalSequenceRule::new(
                        EnglishSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                    Box::new(IllegalSequenceRule::new(
                        PolishSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                ])),
                PasswordData::with_password("p987rw3sśtuwxyzź".to_string()),
                vec![PolishSequenceData::Alphabetical.get_error_code()],
            ),
            // german and english
            RulePasswordTestItem(
                Box::new(PasswordValidator::new(vec![
                    Box::new(IllegalSequenceRule::new(
                        EnglishSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                    Box::new(IllegalSequenceRule::new(
                        GermanSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                ])),
                PasswordData::with_password("P987xyzäö".to_string()),
                vec![GermanSequenceData::Alphabetical.get_error_code()],
            ),
            // czech and english
            RulePasswordTestItem(
                Box::new(PasswordValidator::new(vec![
                    Box::new(IllegalSequenceRule::new(
                        EnglishSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                    Box::new(IllegalSequenceRule::new(
                        CzechSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                ])),
                PasswordData::with_password("ABCx12y34zcčdĎeě".to_string()),
                vec![CzechSequenceData::Alphabetical.get_error_code()],
            ),
            // cyrillic and english
            RulePasswordTestItem(
                Box::new(PasswordValidator::new(vec![
                    Box::new(IllegalSequenceRule::new(
                        EnglishSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                    Box::new(IllegalSequenceRule::new(
                        CyrillicSequenceData::Alphabetical,
                        5,
                        true,
                        false,
                    )),
                ])),
                PasswordData::with_password("ABCx12y34zcабвгд".to_string()),
                vec![CyrillicSequenceData::Alphabetical.get_error_code()],
            ),
        ];
        check_passwords(test_cases);
    }

    #[test]
    fn test_messages() {
        let test_cases: Vec<RulePasswordTestItem> = vec![
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::USQwerty,
                )),
                PasswordData::with_password("pkwerty#n65".to_string()),
                vec!["ILLEGAL_QWERTY_SEQUENCE,werty"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::new(
                    EnglishSequenceData::USQwerty,
                    5,
                    true,
                    false,
                )),
                PasswordData::with_password("pkl;'asd65".to_string()),
                vec!["ILLEGAL_QWERTY_SEQUENCE,kl;'asd"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::Alphabetical,
                )),
                PasswordData::with_password("phijkl#n65".to_string()),
                vec!["ILLEGAL_ALPHABETICAL_SEQUENCE,hijkl"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::new(
                    EnglishSequenceData::Alphabetical,
                    5,
                    true,
                    false,
                )),
                PasswordData::with_password("phijklmno#n65".to_string()),
                vec!["ILLEGAL_ALPHABETICAL_SEQUENCE,hijklmno"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::with_sequence_data(
                    EnglishSequenceData::Numerical,
                )),
                PasswordData::with_password("p34567n65".to_string()),
                vec!["ILLEGAL_NUMERICAL_SEQUENCE,34567"],
            ),
            RulePasswordTestItem(
                Box::new(IllegalSequenceRule::new(
                    EnglishSequenceData::Numerical,
                    5,
                    false,
                    false,
                )),
                PasswordData::with_password("p3456789n65".to_string()),
                vec!["ILLEGAL_NUMERICAL_SEQUENCE,3456789"],
            ),
        ];

        check_messages(test_cases);
    }
}

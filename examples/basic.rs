use passay_rs::rule::length::LengthRule;
use passay_rs::rule::PasswordData;
use passay_rs::rule::Rule;

fn main() {
    let rule = LengthRule::new(8, 20);
    let password_data = PasswordData::with_password("SecureP@ssw0rd".to_string());
    let result = rule.validate(&password_data);
    assert!(result.valid());
}

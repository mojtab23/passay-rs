# passay-rs

passay-rs is a Rust library that provides password validation rules, inspired by the original Java library passay. It allows developers to enforce complex password policies such as minimum length, character composition, and exclusion of common words.

## Features

- Validate passwords against a set of rules
- Support for various rule types such as:
  - Minimum and maximum length
  - Character composition (uppercase, lowercase, digits, special characters)
  - Exclusion of common words
  - Check for username or password reuse
  - Whitespace detection
  - Source reference matching
- Customizable rule behavior (e.g., case sensitivity, backwards matching)
- Extensible architecture to support additional rules and languages

## Usage

To use passay-rs, add it to your `Cargo.toml`:

```toml
[dependencies]
passay-rs = "0.1.0"
```

Then, create and configure your password validation rules:

```rust
use passay_rs::rule::character::CharacterRule;
use passay_rs::rule::length::LengthRule;
use passay_rs::rule::password_utils::PasswordUtils;
use passay_rs::rule::rule_result::RuleResult;
use passay_rs::rule::PasswordData;

let mut rule = LengthRule::new(8, 12);
rule.add_rule(CharacterRule::new());
let password_data = PasswordData::with_password("SecureP@ssw0rd");
let result = rule.validate(&password_data);
```

## Contributing

We welcome contributions! If you're interested in helping with the project, please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file for more information.

## License
This project is licensed under your choice of either the MIT License or the Apache License 2.0. This approach provides users with flexibility and is common in the Rust ecosystem.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
## Notes

This project is in early stages of development and there might be bugs and missing documentation. It's not recommended to be used in production.

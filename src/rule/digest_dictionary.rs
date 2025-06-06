// It's not seem safe to implement
// TODO If implemented add this trait to it to mark it as Dictionary for entropy
// add this to Rule trait impl
//     fn as_dictionary_rule<'a>(&'a self) -> Option<&'a dyn DictionaryRuleTrait> {
//         Some(self)
//     }
////////
// impl<D: Dictionary> DictionaryRuleTrait for DigestDictionaryRule<D> {
//     fn dictionary(&self) -> &dyn Dictionary {
//         &self.dictionary
//     }
// }

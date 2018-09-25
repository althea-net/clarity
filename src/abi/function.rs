use abi::item::Item;

/// A function builder that holds a reference to an existing item of the contract.
///
/// This way we can inspect the required inputs on a function, and encode the
/// parameters.
pub struct Function<'a> {
    pub item: &'a Item,
}

impl<'a> Function<'a> {
    pub fn new(item: &'a Item) -> Function {
        Function { item }
    }
}

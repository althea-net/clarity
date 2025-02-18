#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

extern crate syn_solidity;

/// Tools for working with `#[...]` attributes.
mod attr;
pub use attr::{
    derives_mapped, docs_str, mk_doc, parse_derives, CasingStyle, ContainsSolAttrs, SolAttrs,
};

mod input;
pub use input::{SolInput, SolInputKind};

mod expander;
pub use expander::SolInputExpander;

mod json;
pub use json::tokens_for_sol;

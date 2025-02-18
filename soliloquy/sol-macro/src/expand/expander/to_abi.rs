use super::ExpCtxt;
use crate::expand::verbatim::Verbatim;
use alloy_json_abi::{
    Constructor, Error, Event, EventParam, Fallback, Function, Param, Receive, StateMutability,
};
use proc_macro2::TokenStream;
use std::fmt::Write;
use syn_solidity::{ItemError, ItemEvent, ItemFunction};

pub(crate) fn generate<T>(t: &T, cx: &ExpCtxt<'_>) -> TokenStream
where
    T: ToAbi,
    T::DynAbi: Verbatim,
{
    crate::expand::verbatim::verbatim(&t.to_dyn_abi(cx), &cx.crates)
}

pub(crate) trait ToAbi {
    type DynAbi;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi;
}

impl ToAbi for syn_solidity::ItemFunction {
    type DynAbi = Function;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi {
        Function {
            name: self
                .name
                .as_ref()
                .map(|i| i.as_string())
                .unwrap_or_default(),
            inputs: self.parameters.to_dyn_abi(cx),
            outputs: self
                .returns
                .as_ref()
                .map(|r| r.returns.to_dyn_abi(cx))
                .unwrap_or_default(),
            state_mutability: self.attributes.to_dyn_abi(cx),
        }
    }
}

impl ToAbi for syn_solidity::ItemError {
    type DynAbi = Error;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi {
        Error {
            name: self.name.as_string(),
            inputs: self.parameters.to_dyn_abi(cx),
        }
    }
}

impl ToAbi for syn_solidity::ItemEvent {
    type DynAbi = Event;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi {
        Event {
            name: self.name.as_string(),
            inputs: self.parameters.iter().map(|e| e.to_dyn_abi(cx)).collect(),
            anonymous: self.is_anonymous(),
        }
    }
}

impl<P> ToAbi for syn_solidity::Parameters<P> {
    type DynAbi = Vec<Param>;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi {
        self.iter().map(|p| p.to_dyn_abi(cx)).collect()
    }
}

impl ToAbi for syn_solidity::VariableDeclaration {
    type DynAbi = Param;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi {
        ty_to_param(
            self.name.as_ref().map(syn_solidity::SolIdent::as_string),
            &self.ty,
            cx,
        )
    }
}

impl ToAbi for syn_solidity::EventParameter {
    type DynAbi = EventParam;

    fn to_dyn_abi(&self, cx: &ExpCtxt<'_>) -> Self::DynAbi {
        let name = self.name.as_ref().map(syn_solidity::SolIdent::as_string);
        let Param {
            ty,
            name,
            components,
            internal_type,
        } = ty_to_param(name, &self.ty, cx);
        EventParam {
            ty,
            name,
            indexed: self.is_indexed(),
            internal_type,
            components,
        }
    }
}

impl ToAbi for syn_solidity::FunctionAttributes {
    type DynAbi = StateMutability;

    fn to_dyn_abi(&self, _cx: &ExpCtxt<'_>) -> Self::DynAbi {
        match self.mutability() {
            Some(syn_solidity::Mutability::Pure(_) | syn_solidity::Mutability::Constant(_)) => {
                StateMutability::Pure
            }
            Some(syn_solidity::Mutability::View(_)) => StateMutability::View,
            Some(syn_solidity::Mutability::Payable(_)) => StateMutability::Payable,
            None => StateMutability::NonPayable,
        }
    }
}

fn ty_to_param(name: Option<String>, ty: &syn_solidity::Type, cx: &ExpCtxt<'_>) -> Param {
    let mut ty_name = ty_abi_string(ty, cx);

    // HACK: `cx.custom_type` resolves the custom type recursively, so in recursive structs the
    // peeled `ty` will be `Tuple` rather than `Custom`.
    if ty_name.starts_with('(') {
        let paren_i = ty_name.rfind(')').expect("malformed tuple type");
        let suffix = &ty_name[paren_i + 1..];
        ty_name = format!("tuple{suffix}");
    }

    let mut component_names = vec![];
    let resolved = match ty.peel_arrays() {
        syn_solidity::Type::Custom(name) => {
            if let syn_solidity::Item::Struct(s) = cx.item(name) {
                component_names = s
                    .fields
                    .names()
                    .map(|n| n.map(|i| i.as_string()).unwrap_or_default())
                    .collect();
            }
            cx.custom_type(name)
        }
        ty => ty,
    };

    let components = if let syn_solidity::Type::Tuple(tuple) = resolved {
        tuple
            .types
            .iter()
            .enumerate()
            .map(|(i, ty)| ty_to_param(component_names.get(i).cloned(), ty, cx))
            .collect()
    } else {
        vec![]
    };

    // TODO: internal_type
    let internal_type = None;

    Param {
        ty: ty_name,
        name: name.unwrap_or_default(),
        internal_type,
        components,
    }
}

fn ty_abi_string(ty: &syn_solidity::Type, cx: &ExpCtxt<'_>) -> String {
    let mut suffix = String::new();
    rec_ty_abi_string_suffix(cx, ty, &mut suffix);

    let mut ty = ty.peel_arrays();
    if let syn_solidity::Type::Custom(name) = ty {
        match cx.try_custom_type(name) {
            Some(syn_solidity::Type::Tuple(_)) => return format!("tuple{suffix}"),
            Some(custom) => ty = custom,
            None => {}
        }
    }
    format!("{}{suffix}", super::ty::TypePrinter::new(cx, ty))
}

fn rec_ty_abi_string_suffix(cx: &ExpCtxt<'_>, ty: &syn_solidity::Type, s: &mut String) {
    if let syn_solidity::Type::Array(array) = ty {
        rec_ty_abi_string_suffix(cx, &array.ty, s);
        if let Some(size) = cx.eval_array_size(array) {
            write!(s, "[{size}]").unwrap();
        } else {
            s.push_str("[]");
        }
    }
}

pub(super) fn constructor(function: &ItemFunction, cx: &ExpCtxt<'_>) -> Constructor {
    assert!(function.kind.is_constructor());
    Constructor {
        inputs: function.parameters.to_dyn_abi(cx),
        state_mutability: function.attributes.to_dyn_abi(cx),
    }
}

pub(super) fn fallback(function: &ItemFunction, _cx: &ExpCtxt<'_>) -> Fallback {
    assert!(function.kind.is_fallback());
    Fallback {
        state_mutability: StateMutability::NonPayable,
    }
}

pub(super) fn receive(function: &ItemFunction, _cx: &ExpCtxt<'_>) -> Receive {
    assert!(function.kind.is_receive());
    Receive {
        state_mutability: StateMutability::Payable,
    }
}

macro_rules! make_map {
    ($items:ident, $cx:ident) => {{
        let mut map = std::collections::BTreeMap::<String, Vec<_>>::new();
        for item in $items {
            let item = item.to_dyn_abi($cx);
            map.entry(item.name.clone()).or_default().push(item);
        }
        crate::expand::verbatim::verbatim(&map, &$cx.crates)
    }};
}

pub(super) fn functions_map(functions: &[ItemFunction], cx: &ExpCtxt<'_>) -> TokenStream {
    make_map!(functions, cx)
}

pub(super) fn events_map(events: &[&ItemEvent], cx: &ExpCtxt<'_>) -> TokenStream {
    make_map!(events, cx)
}

pub(super) fn errors_map(errors: &[&ItemError], cx: &ExpCtxt<'_>) -> TokenStream {
    make_map!(errors, cx)
}

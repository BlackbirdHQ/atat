use crate::proc_macro2::{Literal, TokenStream, TokenTree};
use syn::{spanned::Spanned, Error, FieldsNamed, Ident, Result, Type};

pub fn stream_from_tokens(tokens: &proc_macro2::TokenStream) -> TokenStream {
    for f in tokens.clone() {
        if let TokenTree::Group(g) = f {
            return g.stream();
        }
    }
    panic!("Cannot find stream from tokens!");
}

pub fn get_lit(tokens: &proc_macro2::TokenStream) -> Result<Literal> {
    for l in stream_from_tokens(&tokens) {
        if let TokenTree::Literal(lit) = l {
            return Ok(lit);
        }
    }
    Err(Error::new(tokens.span(), "Cannot find AT Command!"))
}

pub fn get_ident(tokens: &proc_macro2::TokenStream) -> Result<Ident> {
    for l in stream_from_tokens(tokens) {
        if let TokenTree::Ident(ident) = l {
            return Ok(ident);
        }
    }
    Err(Error::new(tokens.span(), "Cannot find ident type!"))
}

pub fn get_name_ident_lit(tokens: &proc_macro2::TokenStream, needle: &str) -> Result<Literal> {
    let mut found = false;
    for l in stream_from_tokens(tokens) {
        match l {
            TokenTree::Ident(i) => {
                if i.to_string() == needle {
                    found = true;
                }
            }
            TokenTree::Literal(lit) => {
                if found {
                    return Ok(lit);
                } else {
                    found = false;
                }
            }
            TokenTree::Punct(p) => {
                if p.to_string() == "=" && found {
                    found = true;
                } else {
                    found = false;
                }
            }
            _ => {
                found = false;
            }
        }
    }
    Err(Error::new(tokens.span(), "Cannot find literal type!"))
}

pub fn get_field_names(fields: Option<&FieldsNamed>) -> (Vec<Ident>, Vec<Type>, Vec<String>) {
    if let Some(fields) = fields {
        let (mut field_name_pos, mut field_type_pos): (Vec<(Ident, usize)>, Vec<(Type, usize)>) = {
            (
                fields
                    .named
                    .iter()
                    .map(|field| {
                        (
                            field.ident.clone().unwrap(),
                            if let Some(attr) =
                                field.attrs.iter().find(|attr| attr.path.is_ident("at_arg"))
                            {
                                match syn::parse_str::<syn::Lit>(
                                    &get_name_ident_lit(&attr.tokens, "position")
                                        .unwrap()
                                        .to_string(),
                                )
                                .unwrap()
                                {
                                    syn::Lit::Int(l) => l.base10_parse::<usize>().unwrap(),
                                    _ => panic!("Position argument must be an integer!"),
                                }
                            } else {
                                0
                            },
                        )
                    })
                    .collect(),
                fields
                    .named
                    .iter()
                    .map(|field| {
                        (
                            field.ty.clone(),
                            if let Some(attr) =
                                field.attrs.iter().find(|attr| attr.path.is_ident("at_arg"))
                            {
                                match syn::parse_str::<syn::Lit>(
                                    &get_name_ident_lit(&attr.tokens, "position")
                                        .unwrap()
                                        .to_string(),
                                )
                                .unwrap()
                                {
                                    syn::Lit::Int(l) => l.base10_parse::<usize>().unwrap(),
                                    _ => panic!("Position argument must be an integer!"),
                                }
                            } else {
                                0
                            },
                        )
                    })
                    .collect(),
            )
        };

        field_name_pos.sort_by(|(_, a), (_, b)| a.cmp(b));
        field_type_pos.sort_by(|(_, a), (_, b)| a.cmp(b));
        let (field_name, _): (Vec<Ident>, Vec<usize>) = field_name_pos.iter().cloned().unzip();
        let (field_type, _): (Vec<Type>, Vec<usize>) = field_type_pos.iter().cloned().unzip();

        let field_name_str: Vec<String> = field_name.iter().map(|n| n.to_string()).collect();

        (field_name, field_type, field_name_str)
    } else {
        (vec![], vec![], vec![])
    }
}

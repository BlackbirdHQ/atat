use crate::proc_macro::TokenStream;
use crate::proc_macro2::Literal;
use quote::quote;

use syn::{Attribute, Data, DataEnum, DeriveInput, Fields, Ident, Type, Variant};

use crate::helpers::get_lit;

#[derive(Debug)]
struct AtUrcAttr {
    pub variant_name: Ident,
    pub variant_field_type: Type,
    pub cmd: Literal,
}

fn get_type(variant: &Variant) -> Type {
    if variant.fields.len() > 1 {
        panic!("AtatUrc does not support more than one field per variant");
    }
    match variant.fields {
        Fields::Unnamed(ref f) => f
            .unnamed
            .first()
            .expect(
                "AtatUrc does not support unit variants, \
                please add unnamed field to a struct, \
                implementing AtatResp",
            )
            .ty
            .clone(),
        _ => panic!("AtatUrc does not support named fields in variants"),
    }
}

pub fn atat_urc(item: DeriveInput) -> TokenStream {
    match item.data {
        Data::Enum(DataEnum { variants, .. }) => {
            let urc_attrs: Vec<AtUrcAttr> = variants
                .iter()
                .map(|variant| AtUrcAttr {
                    cmd: get_urc_code(&variant.attrs),
                    variant_field_type: get_type(&variant),
                    variant_name: variant.ident.clone(),
                })
                .collect();
            generate_urc_output(&item.ident, &item.generics, &urc_attrs)
        }
        _ => {
            panic!("AtatUrc can only be applied to enums!");
        }
    }
}

fn get_urc_code(attrs: &[Attribute]) -> Literal {
    if let Some(Attribute { tokens, .. }) = attrs.iter().find(|attr| attr.path.is_ident("at_urc")) {
        get_lit(&tokens).expect("Failed to find non-optional at_urc attribute on all variants!")
    } else {
        panic!("Failed to find non-optional at_urc attribute on all variants!")
    }
}

fn generate_urc_output(
    name: &Ident,
    generics: &syn::Generics,
    urc_attrs: &[AtUrcAttr],
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let variant_names: Vec<Ident> = urc_attrs.iter().map(|a| a.variant_name.clone()).collect();
    let variant_field_types: Vec<Type> = urc_attrs
        .iter()
        .map(|a| a.variant_field_type.clone())
        .collect();
    let cmds: Vec<Literal> = urc_attrs.iter().map(|a| a.cmd.clone()).collect();

    TokenStream::from(quote! {
        #[automatically_derived]
        impl #impl_generics atat::AtatUrc for #name #ty_generics #where_clause {
            type Response = #name;

            fn parse(resp: &[u8]) -> ::core::result::Result<Self::Response, atat::Error> {
                if let Some(index) = resp.iter().position(|&x| x == b':') {
                    Ok(match &resp[..index] {
                        #(
                            #cmds => #name::#variant_names(serde_at::from_slice::<#variant_field_types>(resp).map_err(|e| {
                                atat::Error::ParseString
                            })?),
                        )*
                        _ => return Err(atat::Error::InvalidResponse)
                    })
                } else {
                    Err(atat::Error::InvalidResponse)
                }
            }
        }
    })
}

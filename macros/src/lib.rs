use core::panic;

use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse_macro_input, AngleBracketedGenericArguments, DeriveInput, FnArg, GenericArgument, Ident,
    ItemTrait, LitStr, Pat, PatType, PathArguments, PathSegment, Receiver, ReturnType, TraitItem,
    Type, TypePath, TypeReference,
};

fn get_table_attr(input: &DeriveInput, name: &str) -> String {
    input
        .attrs
        .iter()
        .find(|v| v.path().is_ident("table"))
        .map(|v| {
            v.parse_args::<LitStr>()
                .expect("The table atribute needs a single string parameter")
        })
        .map(|v| v.value())
        .unwrap_or_else(|| name.to_case(Case::Snake))
}

// fn get_primary_key(input: &[Attribute], name: &str) -> String {
//     input
//         .iter()
//         .find(|v| v.path().is_ident("column"))
//         .filter(|v| {
//             v.parse_args::<Ident>()
//                 .expect("Column attribute takes a parameter").to_string() == "primary"
//         })
//         .map(|v| v.)
//         .unwrap_or_else(|| name.to_case(Case::Snake))
// }

fn generate_parameter_list(st: &[ColumnField], delimeter: &str, prefix: Option<&str>) -> String {
    let mut insert = String::with_capacity(
        st.iter()
            .map(|v| v.get_ident())
            .map(|v| v.span().source_text().map(|v| v.len()).unwrap_or(0))
            .sum::<usize>()
            + delimeter.len() * st.len(),
    );
    for (c, name) in st.iter().enumerate() {
        if let Some(prefix) = prefix {
            insert.push_str(prefix);
        }
        insert.push_str(&name.get_ident().to_string());
        if c < st.len() - 1 {
            insert.push_str(delimeter);
        }
    }
    insert
}

fn generate_crud_impl(st: &[ColumnField], name: &Ident, table_attr: &str) -> impl ToTokens {
    let types = generate_parameter_list(st, ", ", None);
    let values = generate_parameter_list(st, ", ", Some(":"));
    let primary = st
        .iter()
        .find(|p| p.is_primary())
        .map(|v| v.get_ident())
        .expect("cannot update without primary key");

    let primary_str = format!(":{}", primary);
    let cols = st
        .iter()
        .map(|v| v.get_ident())
        .map(|v| format!("{} = :{}", v, v))
        .collect::<Vec<String>>()
        .join(",");

    let insert = format!("INSERT INTO {} ({}) values ({})", table_attr, types, values);

    let insert_update = format!(
        "INSERT OR REPLACE INTO {} ({}) values ({})",
        table_attr, types, values
    );
    let insert_ignore = format!(
        "INSERT INTO {} ({}) values ({}) ON CONFLICT({}) DO NOTHING",
        table_attr, types, values, primary
    );

    let update = format!(
        "UPDATE {} set {} where {} = :{}",
        table_attr, cols, primary, primary
    );

    let delete = format!(
        "DELETE FROM {}  where {} = :{}",
        table_attr, primary, primary
    );

    // panic!("{}", insert);
    quote! {
        #[automatically_derived]
        impl crate::api::db::connection::Crud for #name {
            fn insert(&self, conn: &crate::api::db::connection::SqliteDb) -> anyhow::Result<()> {
                use crate::api::db::entities::GetParams;
                conn.0.conn.lock().unwrap().execute(#insert, self.get_params().as_slice())?;
                Ok(())
            }

            fn insert_on_conflict(&self, conn: &crate::api::db::connection::SqliteDb, on_conflict: crate::api::db::connection::OnConflict) -> anyhow::Result<()> {
                use crate::api::db::entities::GetParams;
                match on_conflict {
                    crate::api::db::connection::OnConflict::Abort => conn.0.conn.lock().unwrap().execute(#insert, self.get_params().as_slice())?,
                    crate::api::db::connection::OnConflict::Ignore => conn.0.conn.lock().unwrap().execute(#insert_ignore, self.get_params().as_slice())?,
                    crate::api::db::connection::OnConflict::Update => conn.0.conn.lock().unwrap().execute(#insert_update, self.get_params().as_slice())?
                };
                Ok(())
            }

            fn update(&self, conn: &crate::api::db::connection::SqliteDb) -> anyhow::Result<()> {
                use crate::api::db::entities::GetParams;
                conn.0.conn.lock().unwrap().execute(#update, self.get_params().as_slice())?;
                Ok(())
            }

            fn delete(self, conn: &crate::api::db::connection::SqliteDb) -> anyhow::Result<()> {
                use crate::api::db::entities::GetParams;
                conn.0.conn.lock().unwrap().execute(#delete, &[(#primary_str, &self . #primary)])?;
                Ok(())
            }
        }
    }
}

fn generate_from_row(st: &[ColumnField], name: &Ident) -> impl ToTokens {
    let rows = st.iter().map(|v| v.get_ident()).enumerate().map(|(n, f)| {
        quote! {
            #f: row.get(#n)?
        }
    });
    quote! {
        #[automatically_derived]
        #[flutter_rust_bridge::frb(ignore)]
        impl crate::api::db::entities::FromRow for #name {
            fn from_row(row: &::rusqlite::Row) -> crate::error::Result<Self> {
                let s = Self { #( #rows ),* };
                Ok(s)
            }
        }
    }
}

fn generate_getparams(st: &[ColumnField], name: &Ident) -> impl ToTokens {
    let params = st.iter().map(|v| v.get_ident());
    let names = st.iter().map(|f| format!(":{}", f.get_ident().to_string()));
    quote! {
        #[automatically_derived]
        #[flutter_rust_bridge::frb(ignore)]
        impl crate::api::db::entities::GetParams for #name {
             fn get_params<'a>(&'a self) -> Vec<(&'a str, &'a dyn ::rusqlite::ToSql)> {
                 vec![ #( (#names, &self. #params ) ),* ]
            }
         }

    }
}

enum ColumnField {
    PrimaryKey(Ident),
    Column(Ident),
    Nullable(Ident),
}

impl ColumnField {
    fn get_ident(&self) -> &'_ Ident {
        match self {
            Self::PrimaryKey(ref i) => i,
            Self::Column(ref i) => i,
            Self::Nullable(ref i) => i,
        }
    }

    fn is_primary(&self) -> bool {
        match self {
            Self::PrimaryKey(_) => true,
            Self::Column(_) => false,
            Self::Nullable(_) => false,
        }
    }
}

#[proc_macro_derive(FromRow, attributes(table, primary))]
pub fn from_row(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let table_attr = get_table_attr(&input, &input.ident.to_string());
    let st = match input.data {
        syn::Data::Enum(_) => panic!("FromRow does not work on enums"),
        syn::Data::Union(_) => panic!("FromRow does not work on unions"),
        syn::Data::Struct(s) => s
            .fields
            .into_iter()
            .map(|f| {
                let ident = f.ident.expect("tuple structs are not supported");
                let mut nullable = false;
                if let Type::Path(TypePath { path, .. }) = f.ty {
                    if path.is_ident("Option") {
                        nullable = true;
                    }
                }
                if f.attrs
                    .iter()
                    .find(|v| v.path().is_ident("primary"))
                    .is_some()
                {
                    ColumnField::PrimaryKey(ident)
                } else {
                    if nullable {
                        ColumnField::Nullable(ident)
                    } else {
                        ColumnField::Column(ident)
                    }
                }
            })
            .collect::<Vec<_>>(),
    };

    let get_params = generate_getparams(&st, &input.ident);
    let from_row = generate_from_row(&st, &input.ident);
    let crud_impl = generate_crud_impl(&st, &input.ident, &table_attr);

    quote! {
        #get_params

        #from_row

        #crud_impl
    }
    .into()
}

// #[proc_macro_derive(Dao, attributes(query))]
// pub fn dao(item: TokenStream) -> TokenStream {
//     let input = parse_macro_input!(item as DeriveInput);

//     match input.data {
//         syn::Data::Struct(st) => {

//         }
//         _ => panic!("only structs are supported for Dao"),
//     }

//     quote! {}.into()
// }

// struct ManyStmnt {
//     statements: Vec<Stmt>,
// }

// impl Parse for ManyStmnt {
//     fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
//         let mut res = Vec::new();
//         while let Ok(s) = input.parse::<Stmt>() {
//             res.push(s);
//         }
//         res.push(input.parse()?);
//         Ok(ManyStmnt { statements: res })
//     }
// }

#[proc_macro_attribute]
pub fn query(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

// struct QueryArgs {
//     query: LitStr,
//     middle: Token![,],
//     ret: Path,
// }

// impl Parse for QueryArgs {
//     fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
//         Ok(Self {
//             query: input.parse()?,
//             middle: input.parse()?,
//             ret: input.parse()?,
//         })
//     }
// }

fn get_type_from_arguments(arguments: &PathArguments) -> Type {
    match arguments {
        PathArguments::AngleBracketed(AngleBracketedGenericArguments { args, .. }) => {
            match args.first().expect("no generic argument") {
                GenericArgument::Type(ty) => ty.clone(),
                _ => panic!("must be a type"),
            }
        }
        _ => panic!("failed to parse option"),
    }
}

enum RetVal {
    Nullable(Type),
    Many(Type),
    One(Type),
    Unit,
}

enum VecOr {
    Ident(Ident),
    Vec(Ident),
}

impl VecOr {
    fn ident(&self) -> &'_ Ident {
        match self {
            Self::Ident(ref i) => i,
            Self::Vec(ref i) => i,
        }
    }
}

impl VecOr {
    fn from_ident(p: &Ident, ty: &Box<Type>) -> Self {
        if let Type::Path(path) = ty.as_ref() {
            let id = &path
                .path
                .segments
                .last()
                .as_ref()
                .expect("missing path segment")
                .ident;
            if id.to_string().as_str() == "Vec" {
                Self::Vec(p.clone())
            } else {
                VecOr::Ident(p.clone())
            }
        } else {
            VecOr::Ident(p.clone())
        }
    }
}

fn get_fn_arg_type(arg: &FnArg, require: Option<&str>) -> VecOr {
    match arg {
        syn::FnArg::Receiver(Receiver { ty, self_token, .. }) => match ty.as_ref() {
            Type::Path(TypePath { path, .. }) => {
                if let Some(require) = require {
                    if !path.is_ident(require) {
                        panic!("dao functions must have a SqliteDb parameter")
                    }
                }
                VecOr::Ident(self_token.clone().into())
            }
            Type::Reference(TypeReference { elem, .. }) => match elem.as_ref() {
                Type::Path(TypePath { path, .. }) => {
                    if let Some(require) = require {
                        if !path.is_ident(require) {
                            panic!("dao functions must have a SqliteDb parameter")
                        }
                    }

                    VecOr::Ident(self_token.clone().into())
                }
                _ => panic!("types must be a full path"),
            },
            _ => panic!("types must be a full path"),
        },
        syn::FnArg::Typed(PatType { ty, pat, .. }) => match ty.as_ref() {
            Type::Path(TypePath { path, .. }) => {
                if let Some(require) = require {
                    if !path.is_ident(require) {
                        panic!("dao functions must have a SqliteDb parameter")
                    }
                }

                match pat.as_ref() {
                    Pat::Ident(ident) => VecOr::from_ident(&ident.ident, ty),
                    _ => panic!("function parameter should have a name"),
                }
            }
            Type::Reference(TypeReference { elem, .. }) => match elem.as_ref() {
                Type::Path(TypePath { path, .. }) => {
                    if let Some(require) = require {
                        if !path.is_ident(require) {
                            panic!("dao functions must have a SqliteDb parameter")
                        }
                    }

                    match pat.as_ref() {
                        Pat::Ident(ident) => VecOr::from_ident(&ident.ident, ty),
                        _ => panic!("function parameter should have a name"),
                    }
                }
                _ => panic!("types must be a full path"),
            },
            _ => panic!("types must be a full path"),
        },
    }
}

// fn get_fn_type(f: &TraitItemFn, require: Option<&str>) -> Ident {
//     get_fn_arg_type(f.sig.inputs.get(0).unwrap(), require)
// }

#[proc_macro_attribute]
pub fn dao(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut i = parse_macro_input!(item as ItemTrait);
    i.supertraits
        .push(syn::TypeParamBound::Trait(syn::parse_quote! {
            crate::api::db::connection::Dao
        }));
    for traititem in i.items.iter_mut() {
        if let TraitItem::Fn(f) = traititem {
            if let Some(attr) = f
                .attrs
                .iter()
                .find(|a| a.path().is_ident("query"))
                .map(|v| {
                    v.parse_args::<LitStr>()
                        .expect("query attribute requires litstr parameter")
                })
            {
                if f.sig.inputs.len() < 1 {
                    panic!("dao functions should take a single argument")
                }

                let parameters = &f
                    .sig
                    .inputs
                    .iter()
                    .skip(1)
                    .map(|v| get_fn_arg_type(v, None))
                    .collect::<Vec<VecOr>>();

                let pnames = parameters
                    .iter()
                    .map(|v| v.ident())
                    .map(|v| format!(":{}", v));

                let ptransforms = parameters.iter().map(|v| match v {
                    VecOr::Vec(v) => {
                        quote! {
                            let #v = ::std::rc::Rc::new(#v);
                        }
                    }
                    VecOr::Ident(_) => quote! {},
                });

                let parameters = parameters.iter().map(|p| p.ident());

                let query = attr.value();
                let ret = match f.sig.output {
                    ReturnType::Default => panic!("function should have a return type"),
                    ReturnType::Type(_, ref ty) => match ty.as_ref() {
                        Type::Path(ty) => &ty.path,
                        _ => panic!("return type must be an owned type"),
                    },
                };

                let r = match ret.segments.last() {
                    Some(PathSegment { ident, arguments }) => {
                        if ident.to_string() != "Result" {
                            panic!("needs to be a result")
                        }
                        if let Type::Path(TypePath { path, .. }) =
                            get_type_from_arguments(arguments)
                        {
                            match path.segments.last().expect("invalid type") {
                                PathSegment { ident, arguments } => {
                                    match ident.to_string().as_str() {
                                        "Vec" => RetVal::Many(get_type_from_arguments(arguments)),
                                        "Option" => {
                                            RetVal::Nullable(get_type_from_arguments(arguments))
                                        }
                                        _ => {
                                            RetVal::One(Type::Path(TypePath { qself: None, path }))
                                        }
                                    }
                                }
                            }
                        } else {
                            RetVal::Unit
                        }
                    }

                    _ => panic!("there needs to be a return value"),
                };

                let q = match r {
                    RetVal::Many(r) => syn::parse_quote! {
                        {
                            use crate::api::db::entities::FromRow;
                            let mut conn = self . get_connection().connection();
                            #( #ptransforms )*
                            let mut st = conn.prepare(#query)?;
                            let mut i = st.query_map(::rusqlite::named_params!(#(  #pnames: #parameters ),*), |row| Ok(#r :: from_row(row)?))?;
                            let mut res = Vec::new();
                            for v in i {
                                res.push(v?);
                            }
                            Ok(res)
                        }
                    },
                    RetVal::Nullable(r) => syn::parse_quote! {
                        {
                            use rusqlite::OptionalExtension;
                            use crate::api::db::entities::FromRow;
                            let mut conn = self . get_connection().connection();
                            #( #ptransforms )*

                            let mut st = conn.prepare(#query)?;
                            let i = st.query_row(::rusqlite::named_params!(#(  #pnames: #parameters ),*), |row| Ok(#r :: from_row(row)?)).optional()?;
                            Ok(i)
                        }
                    },
                    RetVal::One(r) => syn::parse_quote! {
                        {
                            use crate::api::db::entities::FromRow;
                            let mut conn = self . get_connection().connection();
                            #( #ptransforms )*

                            let mut st = conn.prepare(#query)?;
                            let i = st.query_row(::rusqlite::named_params!(#(  #pnames: #parameters ),*), |row| Ok(#r :: from_row(row)?))?;
                            Ok(i)
                        }
                    },
                    RetVal::Unit => syn::parse_quote! {
                        {
                            use crate::api::db::entities::FromRow;
                            let mut conn = self . get_connection().connection();
                            #( #ptransforms )*

                            let mut st = conn.prepare(#query)?;
                            st.execute(::rusqlite::named_params!(#(  #pnames: #parameters ),*))?;
                            Ok(())
                        }
                    },
                };
                f.default = Some(q)
            }
        }
    }

    quote! { #i }.into()
}

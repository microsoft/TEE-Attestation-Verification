// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Token-level sync/async module materialisation.
//!
//! [`maybe_async`] emits sibling `_sync` and `_async` modules. The source body is interpreted
//! at that unchanged module depth, so ordinary Rust paths and visibility keep their meaning.

use proc_macro::{Delimiter, Group, Ident, Punct, Spacing, Span, TokenStream, TokenTree};

/// Materialises an inline module for the `sync_crypto` and `async_crypto` capability modes.
///
/// ```text
/// #[maybe_async(
///     sync: { /* mode-specific items */ },
///     async: { /* mode-specific items */ },
/// )]
/// mod api {
///     #[maybe_async_fn]
///     fn call() {
///         mb_await!(operation())
///     }
/// }
/// ```
///
/// The output modules are named `api_sync` and `api_async`. `#[maybe_async_fn]` is removed in
/// both copies and adds `async` in the async copy. Marked functions must be ordinary,
/// non-`const` Rust-ABI functions. `mb_await!(expression)` becomes `(expression)` or
/// `(expression).await`. Macro definitions are copied without inspecting their token bodies.
#[proc_macro_attribute]
pub fn maybe_async(arguments: TokenStream, input: TokenStream) -> TokenStream {
    expand(arguments, input).unwrap_or_else(compile_error)
}

struct Arguments {
    synchronous: TokenStream,
    asynchronous: TokenStream,
}

#[derive(Clone, Copy)]
enum Mode {
    Sync,
    Async,
}

impl Mode {
    fn suffix(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Async => "async",
        }
    }

    fn capability(self) -> &'static str {
        match self {
            Self::Sync => "sync_crypto",
            Self::Async => "async_crypto",
        }
    }
}

fn expand(arguments: TokenStream, input: TokenStream) -> Result<TokenStream, String> {
    let arguments = parse_arguments(arguments)?;
    let module = parse_module(input)?;
    let synchronous = emit_module(&module, arguments.synchronous, Mode::Sync)?;
    let asynchronous = emit_module(&module, arguments.asynchronous, Mode::Async)?;
    Ok(synchronous.into_iter().chain(asynchronous).collect())
}

fn parse_arguments(arguments: TokenStream) -> Result<Arguments, String> {
    let tokens: Vec<_> = arguments.into_iter().collect();
    let mut synchronous = None;
    let mut asynchronous = None;
    let mut index = 0;

    while index < tokens.len() {
        let TokenTree::Ident(key) = &tokens[index] else {
            return Err("expected `sync` or `async`".into());
        };
        index += 1;

        if !matches!(tokens.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == ':') {
            return Err(format!("expected `:` after `{key}`"));
        }
        index += 1;

        let Some(TokenTree::Group(group)) = tokens.get(index) else {
            return Err(format!("expected `{{ ... }}` after `{key}:`"));
        };
        if group.delimiter() != Delimiter::Brace {
            return Err(format!("expected `{{ ... }}` after `{key}:`"));
        }
        index += 1;

        let destination = match key.to_string().as_str() {
            "sync" => &mut synchronous,
            "async" => &mut asynchronous,
            other => {
                return Err(format!(
                    "unknown mode `{other}`; expected `sync` or `async`"
                ))
            }
        };
        if destination.replace(group.stream()).is_some() {
            return Err(format!("duplicate `{key}` prelude"));
        }

        if index < tokens.len() {
            if !matches!(tokens.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == ',')
            {
                return Err("expected `,` between mode preludes".into());
            }
            index += 1;
        }
    }

    Ok(Arguments {
        synchronous: synchronous.ok_or("missing `sync: { ... }` prelude")?,
        asynchronous: asynchronous.ok_or("missing `async: { ... }` prelude")?,
    })
}

struct Module {
    prefix: Vec<TokenTree>,
    name: Ident,
    body: Group,
    suffix: Vec<TokenTree>,
}

fn parse_module(input: TokenStream) -> Result<Module, String> {
    let tokens: Vec<_> = input.into_iter().collect();
    let module_index = tokens
        .iter()
        .position(|token| matches!(token, TokenTree::Ident(ident) if ident.to_string() == "mod"))
        .ok_or("`#[maybe_async]` requires an inline module")?;

    let Some(TokenTree::Ident(name)) = tokens.get(module_index + 1) else {
        return Err("expected a module name after `mod`".into());
    };
    let Some(TokenTree::Group(body)) = tokens.get(module_index + 2) else {
        return Err("`#[maybe_async]` requires an inline module body".into());
    };
    if body.delimiter() != Delimiter::Brace {
        return Err("`#[maybe_async]` requires an inline module body".into());
    }

    Ok(Module {
        prefix: tokens[..=module_index].to_vec(),
        name: name.clone(),
        body: body.clone(),
        suffix: tokens[module_index + 3..].to_vec(),
    })
}

fn emit_module(module: &Module, prelude: TokenStream, mode: Mode) -> Result<TokenStream, String> {
    let mut output: TokenStream = format!("#[cfg({})]", mode.capability())
        .parse()
        .map_err(|_| "failed to build feature gate")?;
    output.extend(module.prefix.iter().cloned());

    let source_name = module.name.to_string();
    let source_name = source_name.strip_prefix("r#").unwrap_or(&source_name);
    output.extend([TokenTree::Ident(Ident::new(
        &format!("{source_name}_{}", mode.suffix()),
        module.name.span(),
    ))]);

    let (inner_attributes, source_body) = split_inner_attributes(module.body.stream());
    let mut body_stream = inner_attributes;
    body_stream.extend(prelude);
    body_stream.extend(transform(source_body, mode)?);
    let mut body = Group::new(Delimiter::Brace, body_stream);
    body.set_span(module.body.span());
    output.extend([TokenTree::Group(body)]);
    output.extend(module.suffix.iter().cloned());
    Ok(output)
}

fn split_inner_attributes(input: TokenStream) -> (TokenStream, TokenStream) {
    let tokens: Vec<_> = input.into_iter().collect();
    let mut index = 0;
    while matches!(tokens.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == '#')
        && matches!(tokens.get(index + 1), Some(TokenTree::Punct(punct)) if punct.as_char() == '!')
        && matches!(
            tokens.get(index + 2),
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket
        )
    {
        index += 3;
    }

    (
        tokens[..index].iter().cloned().collect(),
        tokens[index..].iter().cloned().collect(),
    )
}

fn transform(input: TokenStream, mode: Mode) -> Result<TokenStream, String> {
    let tokens: Vec<_> = input.into_iter().collect();
    let mut output = TokenStream::new();
    let mut index = 0;
    let mut marked_function = false;

    while index < tokens.len() {
        if is_macro_definition(&tokens, index) {
            if marked_function {
                return Err("`#[maybe_async_fn]` must annotate a function".into());
            }
            output.extend(tokens[index..index + 4].iter().cloned());
            index += 4;
            continue;
        }

        if is_marker_attribute(&tokens, index) {
            validate_marked_function_prefix(&tokens, index + 2)?;
            marked_function = true;
            index += 2;
            continue;
        }

        if is_await_marker(&tokens, index) {
            let TokenTree::Group(arguments) = &tokens[index + 2] else {
                unreachable!();
            };
            let inner = transform(arguments.stream(), mode)?;
            let mut grouped = Group::new(Delimiter::None, inner);
            grouped.set_span(arguments.span());
            output.extend([TokenTree::Group(grouped)]);
            if matches!(mode, Mode::Async) {
                output.extend([
                    TokenTree::Punct(Punct::new('.', Spacing::Alone)),
                    TokenTree::Ident(Ident::new("await", arguments.span())),
                ]);
            }
            index += 3;
            continue;
        }

        let token = tokens[index].clone();
        if marked_function
            && matches!(
                &token,
                TokenTree::Ident(ident)
                    if matches!(
                        ident.to_string().as_str(),
                        "async" | "const" | "extern" | "unsafe"
                    )
            )
        {
            return Err(
                "`#[maybe_async_fn]` requires an ordinary non-const Rust-ABI function".into(),
            );
        }
        if marked_function && matches!(&token, TokenTree::Ident(ident) if ident.to_string() == "fn")
        {
            if matches!(mode, Mode::Async) {
                output.extend([TokenTree::Ident(Ident::new("async", token.span()))]);
            }
            marked_function = false;
        }

        match token {
            TokenTree::Group(group) => {
                let mut transformed =
                    Group::new(group.delimiter(), transform(group.stream(), mode)?);
                transformed.set_span(group.span());
                output.extend([TokenTree::Group(transformed)]);
            }
            token => output.extend([token]),
        }
        index += 1;
    }

    if marked_function {
        return Err("`#[maybe_async_fn]` must annotate a function".into());
    }
    Ok(output)
}

fn is_marker_attribute(tokens: &[TokenTree], index: usize) -> bool {
    matches!(tokens.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == '#')
        && matches!(
            tokens.get(index + 1),
            Some(TokenTree::Group(group))
                if group.delimiter() == Delimiter::Bracket
                    && group.stream().to_string() == "maybe_async_fn"
        )
}

fn validate_marked_function_prefix(tokens: &[TokenTree], mut index: usize) -> Result<(), String> {
    while matches!(tokens.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == '#')
        && matches!(
            tokens.get(index + 1),
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket
        )
    {
        index += 2;
    }

    if matches!(tokens.get(index), Some(TokenTree::Ident(ident)) if ident.to_string() == "pub") {
        index += 1;
        if matches!(
            tokens.get(index),
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis
        ) {
            index += 1;
        }
    }

    if matches!(tokens.get(index), Some(TokenTree::Ident(ident)) if ident.to_string() == "fn") {
        Ok(())
    } else {
        Err("`#[maybe_async_fn]` must annotate an ordinary function".into())
    }
}

fn is_await_marker(tokens: &[TokenTree], index: usize) -> bool {
    matches!(tokens.get(index), Some(TokenTree::Ident(ident)) if ident.to_string() == "mb_await")
        && matches!(tokens.get(index + 1), Some(TokenTree::Punct(punct)) if punct.as_char() == '!')
        && matches!(tokens.get(index + 2), Some(TokenTree::Group(_)))
}

fn is_macro_definition(tokens: &[TokenTree], index: usize) -> bool {
    matches!(tokens.get(index), Some(TokenTree::Ident(ident)) if ident.to_string() == "macro_rules")
        && matches!(tokens.get(index + 1), Some(TokenTree::Punct(punct)) if punct.as_char() == '!')
        && matches!(tokens.get(index + 2), Some(TokenTree::Ident(_)))
        && matches!(tokens.get(index + 3), Some(TokenTree::Group(_)))
}

fn compile_error(message: String) -> TokenStream {
    format!("compile_error!({message:?});")
        .parse()
        .unwrap_or_else(|_| {
            let mut stream = TokenStream::new();
            stream.extend([TokenTree::Ident(Ident::new(
                "compile_error",
                Span::call_site(),
            ))]);
            stream
        })
}

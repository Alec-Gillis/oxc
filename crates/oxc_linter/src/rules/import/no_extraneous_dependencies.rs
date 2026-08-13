use std::{
    fs,
    path::{Path, PathBuf},
};

use cow_utils::CowUtils;
use fast_glob::glob_match;
use lazy_regex::Regex;
use nodejs_built_in_modules::is_nodejs_builtin_module;
use oxc_ast::{
    AstKind,
    ast::{Expression, ImportDeclarationSpecifier, TSModuleReference},
};
use oxc_diagnostics::OxcDiagnostic;
use oxc_macros::declare_oxc_lint;
use oxc_resolver::{ResolveOptions, Resolver};
use oxc_span::Span;
use rustc_hash::{FxHashMap, FxHashSet};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    context::LintContext,
    rule::{DefaultRuleConfig, Rule},
};

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
enum PackageDir {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl PackageDir {
    fn paths(&self) -> Vec<PathBuf> {
        match self {
            Self::One(path) => vec![path.clone()],
            Self::Many(paths) => paths.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
enum BoolOrGlobs {
    Bool(bool),
    Globs(Vec<String>),
}

impl BoolOrGlobs {
    fn allows(&self, file_path: &Path, cwd: &Path) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Globs(patterns) => {
                let file = file_path.to_string_lossy().cow_replace('\\', "/").into_owned();
                patterns.iter().any(|pattern| {
                    let cwd_pattern =
                        cwd.join(pattern).to_string_lossy().cow_replace('\\', "/").into_owned();
                    let process_pattern = std::env::current_dir()
                        .unwrap_or_default()
                        .join(pattern)
                        .to_string_lossy()
                        .cow_replace('\\', "/")
                        .into_owned();
                    glob_match(pattern, file.as_bytes())
                        || glob_match(cwd_pattern.as_bytes(), file.as_bytes())
                        || glob_match(process_pattern.as_bytes(), file.as_bytes())
                })
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DependencyFields {
    dependencies: FxHashSet<String>,
    dev_dependencies: FxHashSet<String>,
    optional_dependencies: FxHashSet<String>,
    peer_dependencies: FxHashSet<String>,
    bundled_dependencies: FxHashSet<String>,
}

#[derive(Debug, Default, Clone, Copy)]
struct DeclarationStatus {
    dependencies: bool,
    dev_dependencies: bool,
    optional_dependencies: bool,
    peer_dependencies: bool,
    bundled_dependencies: bool,
}

#[derive(Debug, Clone, Default)]
struct PackageData {
    dependencies: DependencyFields,
    package_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct NoExtraneousDependenciesConfig {
    package_dir: Option<PackageDir>,
    dev_dependencies: Option<BoolOrGlobs>,
    optional_dependencies: Option<BoolOrGlobs>,
    peer_dependencies: Option<BoolOrGlobs>,
    bundled_dependencies: Option<BoolOrGlobs>,
    include_internal: bool,
    include_types: bool,
    whitelist: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NoExtraneousDependencies(Box<NoExtraneousDependenciesConfig>);

impl std::ops::Deref for NoExtraneousDependencies {
    type Target = NoExtraneousDependenciesConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn dependency_set(value: Option<&Value>) -> FxHashSet<String> {
    value
        .and_then(Value::as_object)
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn bundled_dependency_set(value: Option<&Value>) -> FxHashSet<String> {
    match value {
        Some(Value::Array(values)) => {
            values.iter().filter_map(Value::as_str).map(str::to_owned).collect()
        }
        Some(Value::Object(object)) => object.keys().cloned().collect(),
        _ => FxHashSet::default(),
    }
}

fn read_package(path: &Path) -> Result<(DependencyFields, Option<String>), String> {
    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let package: Value = serde_json::from_str(&content).map_err(|error| error.to_string())?;
    let object =
        package.as_object().ok_or_else(|| "package.json must contain an object".to_string())?;
    Ok((
        DependencyFields {
            dependencies: dependency_set(object.get("dependencies")),
            dev_dependencies: dependency_set(object.get("devDependencies")),
            optional_dependencies: dependency_set(object.get("optionalDependencies")),
            peer_dependencies: dependency_set(object.get("peerDependencies")),
            bundled_dependencies: bundled_dependency_set(
                object.get("bundleDependencies").or_else(|| object.get("bundledDependencies")),
            ),
        },
        object.get("name").and_then(Value::as_str).map(str::to_owned),
    ))
}

fn merge_dependencies(target: &mut DependencyFields, source: DependencyFields) {
    target.dependencies.extend(source.dependencies);
    target.dev_dependencies.extend(source.dev_dependencies);
    target.optional_dependencies.extend(source.optional_dependencies);
    target.peer_dependencies.extend(source.peer_dependencies);
    target.bundled_dependencies.extend(source.bundled_dependencies);
}

fn nearest_package_json(path: &Path) -> Option<PathBuf> {
    let mut directory = path.parent();
    while let Some(current) = directory {
        let candidate = current.join("package.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        directory = current.parent();
    }
    None
}

fn package_data(
    ctx: &LintContext,
    config: &NoExtraneousDependenciesConfig,
) -> Result<PackageData, PackageError> {
    let paths = config.package_dir.as_ref().map(PackageDir::paths);
    let package_paths = match paths.as_deref() {
        Some(paths) if !paths.is_empty() => paths
            .iter()
            .map(|path| {
                let path = if path.is_absolute() { path.clone() } else { ctx.cwd().join(path) };
                path.join("package.json")
            })
            .collect::<Vec<_>>(),
        _ => nearest_package_json(ctx.file_path()).into_iter().collect(),
    };

    if package_paths.is_empty() {
        return Ok(PackageData::default());
    }

    let configured_single_path = paths.as_ref().is_some_and(|paths| paths.len() == 1);
    let mut data = PackageData::default();
    for path in package_paths {
        let result = read_package(&path);
        match result {
            Ok((dependencies, _)) => {
                if data.package_root.is_none() {
                    data.package_root = path.parent().map(Path::to_path_buf);
                }
                merge_dependencies(&mut data.dependencies, dependencies);
            }
            Err(_error) if !path.exists() && !configured_single_path => {}
            Err(_error) if !path.exists() => return Err(PackageError::NotFound),
            Err(error) => return Err(PackageError::Unparsable(error)),
        }
    }
    if data.package_root.is_none() && paths.as_ref().is_some_and(|paths| !paths.is_empty()) {
        // With multiple configured package directories, eslint-plugin-import does not report a
        // missing package.json. It still checks imports against an empty dependency set.
        data.package_root = Some(ctx.cwd().to_path_buf());
    }
    Ok(data)
}

#[derive(Debug)]
enum PackageError {
    NotFound,
    Unparsable(String),
}

fn package_name(path: &Path, cache: &mut FxHashMap<PathBuf, Option<String>>) -> Option<String> {
    let package_json = nearest_package_json(path)?;
    if let Some(name) = cache.get(&package_json) {
        return name.clone();
    }
    let name = read_package(&package_json).ok().and_then(|(_, name)| name);
    cache.insert(package_json, name.clone());
    name
}

fn module_name(source: &str) -> &str {
    let mut parts = source.split('/');
    let first = parts.next().unwrap_or(source);
    if first.starts_with('@') {
        let second = parts.next().unwrap_or_default();
        if second.is_empty() {
            first
        } else {
            source.get(..first.len() + 1 + second.len()).unwrap_or(source)
        }
    } else {
        first
    }
}

fn declaration_status(dependencies: &DependencyFields, name: &str) -> DeclarationStatus {
    let mut status = DeclarationStatus::default();
    let parts = name.split('/').collect::<Vec<_>>();
    for index in 0..parts.len() {
        if parts[index].starts_with('@') {
            continue;
        }
        let ancestor = parts[..=index].join("/");
        status.dependencies |= dependencies.dependencies.contains(&ancestor);
        status.dev_dependencies |= dependencies.dev_dependencies.contains(&ancestor);
        status.optional_dependencies |= dependencies.optional_dependencies.contains(&ancestor);
        status.peer_dependencies |= dependencies.peer_dependencies.contains(&ancestor);
        status.bundled_dependencies |= dependencies.bundled_dependencies.contains(&ancestor);
    }
    status
}

fn is_declared(
    status: DeclarationStatus,
    config: &NoExtraneousDependenciesConfig,
    file_path: &Path,
    cwd: &Path,
) -> bool {
    status.dependencies
        || (status.dev_dependencies
            && config.dev_dependencies.as_ref().is_none_or(|option| option.allows(file_path, cwd)))
        || (status.optional_dependencies
            && config
                .optional_dependencies
                .as_ref()
                .is_none_or(|option| option.allows(file_path, cwd)))
        || (status.peer_dependencies
            && config.peer_dependencies.as_ref().is_none_or(|option| option.allows(file_path, cwd)))
        || (status.bundled_dependencies
            && config
                .bundled_dependencies
                .as_ref()
                .is_none_or(|option| option.allows(file_path, cwd)))
}

fn diagnostic(span: Span, message: String, help: &'static str) -> OxcDiagnostic {
    OxcDiagnostic::warn(message).with_help(help).with_label(span)
}

fn package_error_diagnostic(error: PackageError) -> OxcDiagnostic {
    match error {
        PackageError::NotFound => OxcDiagnostic::warn("The package.json file could not be found."),
        PackageError::Unparsable(error) => {
            OxcDiagnostic::warn(format!("The package.json file could not be parsed: {error}"))
        }
    }
}

fn resolve_module(ctx: &LintContext, resolver: &Resolver, source: &str) -> Option<PathBuf> {
    // The module record uses the resolver configured for the current lint service. The fallback
    // covers syntax forms that are not represented in the module record, such as `require()`.
    ctx.module_record()
        .get_loaded_module(source)
        .map(|module| module.resolved_absolute_path.clone())
        .or_else(|| {
            resolver
                .resolve_file(ctx.file_path(), source)
                .ok()
                .map(|resolution| resolution.path().to_path_buf())
        })
}

fn is_internal(source: &str, resolved: Option<&Path>, internal_regex: Option<&Regex>) -> bool {
    internal_regex.is_some_and(|regex| regex.is_match(source))
        || source.starts_with('.')
        || source.starts_with('/')
        || resolved.is_some_and(|path| {
            !path.components().any(|component| component.as_os_str() == "node_modules")
        })
}

fn is_core_module(ctx: &LintContext, source: &str) -> bool {
    source.starts_with("node:")
        || is_nodejs_builtin_module(source)
        || ctx
            .settings()
            .json
            .as_ref()
            .and_then(|settings| settings.get("import-x/core-modules"))
            .and_then(Value::as_array)
            .is_some_and(|modules| {
                let base_name = module_name(source);
                modules.iter().any(|module| module.as_str() == Some(base_name))
            })
}

fn is_type_only_import(import: &oxc_ast::ast::ImportDeclaration<'_>) -> bool {
    import.import_kind.is_type()
        || import.specifiers.as_ref().is_some_and(|specifiers| {
            !specifiers.is_empty()
                && specifiers.iter().all(|specifier| {
                    matches!(specifier, ImportDeclarationSpecifier::ImportSpecifier(specifier) if specifier.import_kind.is_type())
                })
        })
}

fn is_type_only_export(export: &oxc_ast::ast::ExportFromDeclaration<'_>) -> bool {
    export.export_kind.is_type()
        || (!export.specifiers.is_empty()
            && export.specifiers.iter().all(|specifier| specifier.export_kind.is_type()))
}

declare_oxc_lint!(
    /// ### What it does
    ///
    /// Forbid the use of packages that are not declared in the nearest `package.json`.
    ///
    /// ### Why is this bad?
    ///
    /// Undeclared packages make builds dependent on transitive or hoisted dependencies and can
    /// break when the package manager changes its installation layout.
    ///
    /// ### Examples
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```js
    /// import lodash from 'lodash'; // not declared in package.json
    /// import eslint from 'eslint'; // only declared in devDependencies
    ///
    /// const lodash = require('lodash');
    /// export { default } from 'lodash';
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```js
    /// import lodash from 'lodash'; // declared in dependencies
    /// import './local-module.js';
    /// import 'node:fs';
    ///
    /// // Test files may allow devDependencies with a glob option:
    /// // { "devDependencies": ["**/*.test.js"] }
    /// import eslint from 'eslint';
    /// ```
    ///
    /// ### Options
    ///
    /// `packageDir` selects one or more directories containing the `package.json` files to use;
    /// without it, the nearest `package.json` is selected. The dependency-category options can
    /// be booleans or globs that allow dev, optional, peer, or bundled dependencies for matching
    /// files. `includeInternal` checks resolved internal modules, `includeTypes` checks type-only
    /// imports and exports, and `whitelist` exempts named packages.
    ///
    /// Oxc uses its native module graph and resolver. Resolver-specific settings from
    /// `eslint-plugin-import` are not interpreted, but `import-x/core-modules` and
    /// `import-x/internal-regex` settings are supported.
    /// Static no-substitution template-literal `import()` calls and TypeScript import-equals
    /// declarations are also checked.
    // <https://github.com/import-js/eslint-plugin-import/blob/v2.32.0/docs/rules/no-extraneous-dependencies.md>
    NoExtraneousDependencies,
    import,
    restriction,
    config = NoExtraneousDependenciesConfig,
    version = "1.43.0",
    short_description = "Forbid the use of extraneous packages.",
);

impl Rule for NoExtraneousDependencies {
    fn from_configuration(value: Value) -> Result<Self, serde_json::error::Error> {
        serde_json::from_value::<DefaultRuleConfig<Self>>(value).map(DefaultRuleConfig::into_inner)
    }

    fn run_once(&self, ctx: &LintContext) {
        let data = match package_data(ctx, &self.0) {
            Ok(data) => data,
            Err(error) => {
                ctx.diagnostic(package_error_diagnostic(error));
                return;
            }
        };
        if data.package_root.is_none() {
            return;
        }

        let resolver = Resolver::new(ResolveOptions::default());
        let whitelist = self.0.whitelist.iter().collect::<FxHashSet<_>>();
        let internal_regex = ctx
            .settings()
            .json
            .as_ref()
            .and_then(|settings| settings.get("import-x/internal-regex"))
            .and_then(Value::as_str)
            .and_then(|pattern| Regex::new(pattern).ok());
        let mut package_name_cache = FxHashMap::default();
        for node in ctx.nodes().iter() {
            let (source, span, is_type) = match node.kind() {
                AstKind::ImportDeclaration(import) => {
                    (import.source.value.as_str(), import.source.span, is_type_only_import(import))
                }
                AstKind::ExportFromDeclaration(export) => {
                    (export.source.value.as_str(), export.source.span, is_type_only_export(export))
                }
                AstKind::ExportAllDeclaration(export) => {
                    (export.source.value.as_str(), export.source.span, export.export_kind.is_type())
                }
                AstKind::ImportExpression(import) => match &import.source {
                    Expression::StringLiteral(literal) => {
                        (literal.value.as_str(), literal.span, false)
                    }
                    Expression::TemplateLiteral(template)
                        if template.is_no_substitution_template() =>
                    {
                        let Some(source) = template.single_quasi() else {
                            continue;
                        };
                        (source.as_str(), template.span, false)
                    }
                    _ => continue,
                },
                AstKind::CallExpression(call) => {
                    let Some(literal) = call.common_js_require() else { continue };
                    (literal.value.as_str(), literal.span, false)
                }
                AstKind::TSImportEqualsDeclaration(import) => match &import.module_reference {
                    TSModuleReference::ExternalModuleReference(external) => (
                        external.expression.value.as_str(),
                        external.expression.span,
                        import.import_kind.is_type(),
                    ),
                    _ => continue,
                },
                _ => continue,
            };

            if is_type && !self.0.include_types {
                continue;
            }
            if is_core_module(ctx, source) {
                continue;
            }

            let resolved = resolve_module(ctx, &resolver, source);
            if resolved.is_none()
                || (!self.0.include_internal
                    && is_internal(source, resolved.as_deref(), internal_regex.as_ref()))
            {
                continue;
            }

            let source_name = module_name(source);
            let real_name =
                resolved.as_deref().and_then(|path| package_name(path, &mut package_name_cache));
            let source_status = declaration_status(&data.dependencies, source_name);
            let real_status = real_name
                .as_deref()
                .filter(|name| *name != source_name)
                .map_or(DeclarationStatus::default(), |name| {
                    declaration_status(&data.dependencies, name)
                });
            let status = DeclarationStatus {
                dependencies: source_status.dependencies || real_status.dependencies,
                dev_dependencies: source_status.dev_dependencies || real_status.dev_dependencies,
                optional_dependencies: source_status.optional_dependencies
                    || real_status.optional_dependencies,
                peer_dependencies: source_status.peer_dependencies || real_status.peer_dependencies,
                bundled_dependencies: source_status.bundled_dependencies
                    || real_status.bundled_dependencies,
            };

            if is_declared(status, &self.0, ctx.file_path(), ctx.cwd()) {
                continue;
            }
            let package_name = real_name.as_deref().unwrap_or(source_name);
            if whitelist.iter().any(|name| name.as_str() == package_name) {
                continue;
            }
            if status.dev_dependencies
                && self
                    .0
                    .dev_dependencies
                    .as_ref()
                    .is_some_and(|option| !option.allows(ctx.file_path(), ctx.cwd()))
            {
                ctx.diagnostic(diagnostic(
                    span,
                    format!("'{package_name}' should be listed in the project's dependencies, not devDependencies."),
                    "Move the package from devDependencies to dependencies.",
                ));
            } else if status.optional_dependencies
                && self
                    .0
                    .optional_dependencies
                    .as_ref()
                    .is_some_and(|option| !option.allows(ctx.file_path(), ctx.cwd()))
            {
                ctx.diagnostic(diagnostic(
                    span,
                    format!("'{package_name}' should be listed in the project's dependencies, not optionalDependencies."),
                    "Move the package from optionalDependencies to dependencies.",
                ));
            } else {
                ctx.diagnostic(diagnostic(
                    span,
                    format!("'{package_name}' should be listed in the project's dependencies."),
                    "Add the package to dependencies with `npm install`.",
                ));
            }
        }
    }
}

#[test]
fn test() {
    use crate::tester::Tester;
    use serde_json::json;

    let package_dir = std::env::current_dir().unwrap().join("fixtures/import");
    let monorepo = package_dir.join("monorepo");
    let nested_package = monorepo.join("packages/nested-package");
    let bundled_as_array = package_dir.join("bundled-dependencies/as-array-bundle-deps");
    let bundled_as_object = package_dir.join("bundled-dependencies/as-object");
    let bundled_race_condition = package_dir.join("bundled-dependencies/race-condition");
    let pass = vec![
        (r#"import "lodash.cond""#, None),
        (r#"import foo, { bar } from "lodash.cond""#, None),
        (r#"require("lodash.cond")"#, None),
        (r#"var foo = require("lodash.cond")"#, None),
        (r#"export { default } from "lodash.cond""#, None),
        (r#"export * from "lodash.cond""#, None),
        (r#"import("lodash.cond")"#, None),
        (r#"import(moduleName)"#, None),
        (r#"require(moduleName)"#, None),
        (r#"import "fs""#, None),
        (r#"import "./foo""#, None),
        (r#"import "@generated/foo""#, None),
        (r#"import "@generated/foo""#, Some(json!([{ "packageDir": bundled_as_array }]))),
        (r#"import "@generated/foo""#, Some(json!([{ "packageDir": bundled_as_object }]))),
        (r#"import "eslint""#, Some(json!([{ "devDependencies": true }]))),
        (r#"import "jest""#, Some(json!([{ "devDependencies": [package_dir.join("*.ts")] }]))),
        (r#"import "jest""#, Some(json!([{ "devDependencies": ["fixtures/import/*.ts"] }]))),
        (
            r#"import "eslint""#,
            Some(json!([{ "devDependencies": false, "peerDependencies": true }])),
        ),
        (r#"import type T from "not-a-dependency""#, None),
        (r#"export type { T } from "not-a-dependency""#, None),
        (r#"import { type T } from "not-a-dependency""#, None),
        (r#"import "lodash.cond""#, Some(json!([{ "packageDir": [] }]))),
        (
            r#"import "left-pad""#,
            Some(json!([{ "packageDir": [package_dir.join("empty"), monorepo] }])),
        ),
        (r#"import "left-pad""#, Some(json!([{ "packageDir": "fixtures/import/monorepo" }]))),
        (r#"import "eslint""#, Some(json!([{ "peerDependencies": true }]))),
        (r#"import "lodash.isarray""#, Some(json!([{ "optionalDependencies": true }]))),
        (r#"import "@generated/foo""#, Some(json!([{ "bundledDependencies": true }]))),
        (r#"import "react""#, Some(json!([{ "packageDir": nested_package }]))),
        (r#"import "left-pad""#, Some(json!([{ "packageDir": monorepo }]))),
        (r#"import "left-pad""#, Some(json!([{ "packageDir": [nested_package, monorepo] }]))),
        (r#"import "right-pad""#, Some(json!([{ "packageDir": [monorepo, nested_package] }]))),
        (
            r#"import "not-a-dependency""#,
            Some(json!([{ "packageDir": monorepo, "whitelist": ["not-a-dependency"] }])),
        ),
    ];
    let fail = vec![
        (r#"import "not-a-dependency""#, None),
        (r#"var donthaveit = require("@org/not-a-dependency")"#, None),
        (r#"var donthaveit = require("@org/not-a-dependency/foo")"#, None),
        (r#"require("not-a-dependency")"#, None),
        (r#"export { default } from "not-a-dependency""#, None),
        (r#"export * from "not-a-dependency""#, None),
        (r#"import("not-a-dependency")"#, None),
        (r#"import foo = require("not-a-dependency")"#, None),
        (
            r#"import "eslint""#,
            Some(json!([{ "devDependencies": false, "peerDependencies": false }])),
        ),
        (r#"import "jest""#, Some(json!([{ "devDependencies": ["*.js"] }]))),
        (r#"import "lodash.isarray""#, Some(json!([{ "optionalDependencies": false }]))),
        (r#"import "@generated/foo""#, Some(json!([{ "bundledDependencies": false }]))),
        (r#"import "@generated/bar""#, Some(json!([{ "packageDir": bundled_race_condition }]))),
        (
            r#"var eslint = require("lodash.isarray")"#,
            Some(json!([{ "optionalDependencies": false }])),
        ),
        (r#"var glob = require("glob")"#, Some(json!([{ "devDependencies": false }]))),
        (r#"import "./foo""#, Some(json!([{ "includeInternal": true }]))),
        (r#"import type T from "not-a-dependency""#, Some(json!([{ "includeTypes": true }]))),
        (r#"export type { T } from "not-a-dependency""#, Some(json!([{ "includeTypes": true }]))),
        (r#"import { type T } from "not-a-dependency""#, Some(json!([{ "includeTypes": true }]))),
        (
            r#"import "not-a-dependency""#,
            Some(json!([{ "packageDir": package_dir.join("does-not-exist") }])),
        ),
        (
            r#"import "react""#,
            Some(
                json!([{ "packageDir": [package_dir.join("does-not-exist"), package_dir.join("empty-folder")] }]),
            ),
        ),
        (r#"import "react""#, Some(json!([{ "packageDir": package_dir.join("empty") }]))),
        (r#"import "left-pad""#, Some(json!([{ "packageDir": nested_package }]))),
        (r#"import "react""#, Some(json!([{ "packageDir": monorepo }]))),
        (r#"import "foo""#, Some(json!([{ "packageDir": package_dir.join("with-syntax-error") }]))),
    ];

    Tester::new(NoExtraneousDependencies::NAME, NoExtraneousDependencies::PLUGIN, pass, fail)
        .with_import_plugin(true)
        .change_rule_path("index.ts")
        .test_and_snapshot();

    Tester::new(
        NoExtraneousDependencies::NAME,
        NoExtraneousDependencies::PLUGIN,
        vec![(
            r#"import "not-a-dependency""#,
            None,
            Some(json!({ "settings": { "import-x/internal-regex": "^not-a-dependency$" } })),
        )],
        vec![],
    )
    .with_import_plugin(true)
    .change_rule_path("index.ts")
    .test();

    Tester::new(
        NoExtraneousDependencies::NAME,
        NoExtraneousDependencies::PLUGIN,
        vec![
            (
                r#"import "electron""#,
                None,
                Some(json!({ "settings": { "import-x/core-modules": ["electron"] } })),
            ),
            (
                r#"import "@generated/bar/module""#,
                None,
                Some(json!({ "settings": { "import-x/core-modules": ["@generated/bar"] } })),
            ),
            (
                r#"import "@generated/bar/and/sub/path""#,
                None,
                Some(json!({ "settings": { "import-x/core-modules": ["@generated/bar"] } })),
            ),
        ],
        vec![],
    )
    .with_import_plugin(true)
    .change_rule_path("index.ts")
    .test();

    Tester::new(
        NoExtraneousDependencies::NAME,
        NoExtraneousDependencies::PLUGIN,
        vec![("import \"left-pad\"", Some(json!([{ "packageDir": monorepo }])))],
        vec![],
    )
    .with_import_plugin(true)
    .change_rule_path("index.ts")
    .test();

    let _ = package_dir;
}

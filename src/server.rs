//! The MCP tools, built on the official Rust SDK (`rmcp`).

use crate::comar::{self, Level, Library};
use crate::taf::Publication;
use arc_swap::ArcSwapOption;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use std::fmt::Write as _;
use std::sync::Arc;

/// A verified publication together with the index built from it.
pub struct Snapshot {
    pub publication: Publication,
    pub library: Arc<Library>,
}

/// Shared between every MCP session; swapped atomically when a newer publication verifies.
pub type SharedSnapshot = Arc<ArcSwapOption<Snapshot>>;

#[derive(Clone)]
pub struct ComarServer {
    snapshot: SharedSnapshot,
    tool_router: ToolRouter<ComarServer>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetRegulationArgs {
    /// A COMAR citation such as "COMAR 10.09.01.03" or "10.09.01". A regulation returns its
    /// text; a chapter returns all of its regulations; a title or subtitle returns a listing.
    pub citation: String,
    /// Include the administrative history notes (adoption/amendment dates, Maryland Register
    /// citations). Defaults to false.
    #[serde(default)]
    pub include_history: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BrowseArgs {
    /// A title, subtitle or chapter citation, e.g. "26" or "26.11". Omit to list all titles.
    #[serde(default)]
    pub citation: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchArgs {
    /// Words that must all appear in the regulation. Put "exact phrases" in double quotes.
    pub query: String,
    /// Restrict results to a title, subtitle or chapter, e.g. "26" or "10.09".
    #[serde(default)]
    pub within: Option<String>,
    /// Maximum number of results (default 10, max 50).
    #[serde(default)]
    pub limit: Option<u32>,
}

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn tool_error(text: impl Into<String>) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![ContentBlock::text(text.into())]))
}

#[tool_router]
impl ComarServer {
    pub fn new(snapshot: SharedSnapshot) -> Self {
        Self { snapshot, tool_router: Self::tool_router() }
    }

    fn current(&self) -> Result<Arc<Snapshot>, CallToolResult> {
        self.snapshot.load_full().ok_or_else(|| {
            CallToolResult::error(vec![ContentBlock::text(
                "COMAR is still being downloaded and verified. Try again in a minute.",
            )])
        })
    }

    #[tool(description = "Get the text of a Maryland regulation (COMAR) by citation, e.g. \
        \"COMAR 10.09.01.03\". Passing a chapter (\"10.09.01\") returns every regulation in it. \
        All text comes from the publisher-signed edition, verified with TUF.")]
    async fn get_regulation(
        &self,
        Parameters(args): Parameters<GetRegulationArgs>,
    ) -> Result<CallToolResult, McpError> {
        let snap = match self.current() {
            Ok(s) => s,
            Err(e) => return Ok(e),
        };
        let lib = &snap.library;
        let citation = match comar::parse_citation(&args.citation) {
            Ok(c) => c,
            Err(e) => return tool_error(e.to_string()),
        };

        let mut out = String::new();
        if let Some(reg) = lib.regulations.get(&citation) {
            let chapter = &lib.containers[&reg.chapter];
            let _ = writeln!(out, "COMAR {} — {}", reg.citation, reg.heading);
            let _ = writeln!(out, "Chapter {}: {}\n", chapter.citation, chapter.heading);
            out.push_str(&reg.text);
            out.push('\n');
            if args.include_history {
                let history = lib.regulation_history(reg);
                if !history.is_empty() {
                    out.push_str("\nAdministrative history:\n");
                    for a in history {
                        let _ = writeln!(out, "- {}", a.text);
                    }
                }
            }
            append_provenance(&mut out, &snap.publication, &chapter.path);
            return text_result(out);
        }

        let Some(container) = lib.containers.get(&citation) else {
            return tool_error(format!(
                "COMAR {citation} was not found in the current edition. Use `browse` to see what \
                 exists, or `search` to find regulations by keyword."
            ));
        };
        if container.level != Level::Chapter {
            return self.browse(Parameters(BrowseArgs { citation: Some(citation) })).await;
        }

        let _ = writeln!(out, "COMAR {} — {}\n", container.citation, container.heading);
        if container.children.is_empty() {
            out.push_str("(This chapter has no regulations in the current edition.)\n");
        }
        for reg in container.children.iter().filter_map(|c| lib.regulations.get(c)) {
            let _ = writeln!(out, "Regulation {} {}\n{}\n", reg.citation, reg.heading, reg.text);
        }
        if let Some(chapter) = lib.chapters.get(&citation) {
            for a in &chapter.authority {
                let _ = writeln!(out, "Authority: {a}");
            }
            if args.include_history && !chapter.history.is_empty() {
                out.push_str("\nAdministrative history:\n");
                for a in &chapter.history {
                    let _ = writeln!(out, "- {}", a.text);
                }
            }
        }
        append_provenance(&mut out, &snap.publication, &container.path);
        text_result(out)
    }

    #[tool(description = "Browse the structure of COMAR: list all titles, or the subtitles of \
        a title, the chapters of a subtitle, or the regulations of a chapter.")]
    async fn browse(&self, Parameters(args): Parameters<BrowseArgs>) -> Result<CallToolResult, McpError> {
        let snap = match self.current() {
            Ok(s) => s,
            Err(e) => return Ok(e),
        };
        let lib = &snap.library;
        let mut out = String::new();
        let Some(raw) = args.citation.filter(|c| !c.trim().is_empty()) else {
            out.push_str("Code of Maryland Regulations — titles:\n");
            for t in &lib.titles {
                let _ = writeln!(out, "- Title {t}: {}", lib.containers[t].heading);
            }
            append_provenance(&mut out, &snap.publication, "us/md/exec/comar");
            return text_result(out);
        };
        let citation = match comar::parse_citation(&raw) {
            Ok(c) => c,
            Err(e) => return tool_error(e.to_string()),
        };
        let Some(container) = lib.containers.get(&citation) else {
            if lib.regulations.contains_key(&citation) {
                return tool_error(format!(
                    "{citation} is a regulation; use get_regulation to read it."
                ));
            }
            return tool_error(format!("COMAR {citation} was not found in the current edition."));
        };
        let child_kind = match container.level {
            Level::Title => "Subtitles",
            Level::Subtitle => "Chapters",
            _ => "Regulations",
        };
        let _ = writeln!(out, "COMAR {} — {}\n{child_kind}:", container.citation, container.heading);
        for child in &container.children {
            let heading = lib
                .containers
                .get(child)
                .map(|c| c.heading.as_str())
                .or_else(|| lib.regulations.get(child).map(|r| r.heading.as_str()))
                .unwrap_or_default();
            let _ = writeln!(out, "- {child}: {heading}");
        }
        append_provenance(&mut out, &snap.publication, &container.path);
        text_result(out)
    }

    #[tool(description = "Full-text search of COMAR. Every word must appear; use \"double \
        quotes\" for exact phrases. Optionally restrict to a title, subtitle or chapter. Returns \
        citations with snippets; read the full text with get_regulation.")]
    async fn search(&self, Parameters(args): Parameters<SearchArgs>) -> Result<CallToolResult, McpError> {
        let snap = match self.current() {
            Ok(s) => s,
            Err(e) => return Ok(e),
        };
        let within = match args.within.as_deref().map(str::trim).filter(|w| !w.is_empty()) {
            Some(w) => match comar::parse_citation(w) {
                Ok(c) => Some(c),
                Err(e) => return tool_error(e.to_string()),
            },
            None => None,
        };
        let limit = args.limit.unwrap_or(10).clamp(1, 50) as usize;
        let hits = snap.library.search(&args.query, within.as_deref(), limit);
        if hits.is_empty() {
            return tool_error(format!("No regulations matched {:?}.", args.query));
        }
        let mut out = format!("Top {} matches for {:?}:\n\n", hits.len(), args.query);
        for hit in hits {
            let reg = hit.regulation;
            let _ = writeln!(out, "COMAR {} — {}\n  {}\n", reg.citation, reg.heading, hit.snippet);
        }
        append_provenance(&mut out, &snap.publication, "us/md/exec/comar");
        text_result(out)
    }

    #[tool(description = "Show how the served COMAR text was authenticated: the TUF roles and \
        versions that verified, their expiration dates, and the signed git commits.")]
    async fn verification_status(&self) -> Result<CallToolResult, McpError> {
        let snap = match self.current() {
            Ok(s) => s,
            Err(e) => return Ok(e),
        };
        let p = &snap.publication;
        let mut out = String::new();
        let _ = writeln!(out, "Authentication repository: {}", p.auth_repo_url);
        let _ = writeln!(out, "  commit {} ({})", p.auth_commit, p.auth_commit_time);
        let _ = writeln!(out, "Content repository: {}", p.content_repo_url);
        let _ = writeln!(out, "  signed commit {}", p.content_commit);
        for (k, v) in &p.content_target {
            let _ = writeln!(out, "  {k}: {}", v.as_str().map_or_else(|| v.to_string(), str::to_owned));
        }
        let _ = writeln!(out, "Verified at {} with tough (TUF client). Roles:", p.verified_at);
        for r in &p.roles {
            let _ = writeln!(
                out,
                "  {:<10} v{:<6} expires {}{}",
                r.role,
                r.version,
                r.expires,
                if r.expired { "  (EXPIRED)" } else { "" }
            );
        }
        for w in &p.warnings {
            let _ = writeln!(out, "Warning: {w}");
        }
        let lib = &snap.library;
        let _ = writeln!(
            out,
            "Index: {} titles, {} chapters, {} regulations.",
            lib.titles.len(),
            lib.chapters.len(),
            lib.regulations.len()
        );
        text_result(out)
    }
}

fn append_provenance(out: &mut String, p: &Publication, path: &str) {
    let edition = p.target_field("codified-date").or(p.target_field("build-date")).unwrap_or("unknown");
    let _ = write!(
        out,
        "\n---\nSource: {path} @ {} in {} (edition {edition}), authenticated via TUF by {} commit {}.",
        short(&p.content_commit.to_string()),
        p.content_repo,
        p.auth_repo_url.trim_end_matches(".git"),
        short(&p.auth_commit.to_string()),
    );
    if !p.warnings.is_empty() {
        let _ = write!(out, " {} verification warning(s); see verification_status.", p.warnings.len());
    }
    out.push_str(
        "\nCOMAR text © State of Maryland, licensed CC BY-NC-SA 4.0. The official version is at \
         https://regs.maryland.gov/.\n",
    );
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ComarServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::from_build_env()
                    .with_title("COMAR (Code of Maryland Regulations)")
                    .with_website_url("https://regs.maryland.gov/"),
            )
            .with_instructions(
                "Read-only access to the Code of Maryland Regulations (COMAR). Citations look like \
                 Title.Subtitle.Chapter.Regulation, e.g. COMAR 10.09.01.03. Use `search` to find \
                 regulations, `get_regulation` to read them, `browse` to navigate, and \
                 `verification_status` to see how the text was authenticated. Every text comes \
                 from the edition the Maryland Division of State Documents signed with TUF/TAF; \
                 quote the citation and edition when answering.",
            )
    }
}

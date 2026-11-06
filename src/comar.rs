//! An in-memory index of COMAR built from the authenticated `law-xml-codified` commit.
//!
//! Layout of that repository (Open Law Library XML):
//!
//! ```text
//! us/md/exec/comar/<title>/index.xml               Title heading
//! us/md/exec/comar/<title>/<subtitle>/index.xml    Subtitle heading
//! us/md/exec/comar/<title>/<subtitle>/<ch>.xml     Chapter, whose <section>s are regulations
//! ```

use crate::git;
use crate::taf::Publication;
use anyhow::{Context, Result, anyhow};
use roxmltree::{Document, Node};
use std::collections::HashMap;

const COMAR_ROOT: &str = "us/md/exec/comar";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Title,
    Subtitle,
    Chapter,
}

/// A title, subtitle or chapter.
#[derive(Debug)]
pub struct Container {
    pub citation: String,
    pub level: Level,
    pub heading: String,
    pub children: Vec<String>,
    /// Source file in the content repository.
    pub path: String,
}

#[derive(Debug)]
pub struct Chapter {
    pub authority: Vec<String>,
    pub history: Vec<Annotation>,
}

#[derive(Debug)]
pub struct Annotation {
    pub text: String,
    /// `cite/@path` values, e.g. `|10|09|01|.06|C.`, used to tie history to regulations.
    pub cites: Vec<String>,
}

#[derive(Debug)]
pub struct Regulation {
    pub citation: String,
    pub chapter: String,
    pub heading: String,
    pub text: String,
    /// `heading + "\n" + text`, ASCII-lowercased (so byte offsets match `searchable_original`).
    search_lower: String,
    searchable_original: String,
}

pub struct Library {
    pub titles: Vec<String>,
    pub containers: HashMap<String, Container>,
    pub chapters: HashMap<String, Chapter>,
    pub regulations: HashMap<String, Regulation>,
    /// Regulation citations in document order, for deterministic search results.
    order: Vec<String>,
}

pub struct SearchHit<'a> {
    pub regulation: &'a Regulation,
    pub score: usize,
    pub snippet: String,
}

impl Library {
    pub fn load(publication: &Publication) -> Result<Self> {
        let repo = publication.content.to_thread_local();
        let commit = publication.content_commit;
        let mut lib = Library {
            titles: Vec::new(),
            containers: HashMap::new(),
            chapters: HashMap::new(),
            regulations: HashMap::new(),
            order: Vec::new(),
        };

        let mut title_dirs: Vec<_> =
            git::list_dir(&repo, commit, COMAR_ROOT)?.into_iter().filter(|e| e.is_dir).collect();
        title_dirs.sort_by(|a, b| a.name.cmp(&b.name));
        for title_dir in title_dirs {
            let title = title_dir.name.clone();
            let title_path = format!("{COMAR_ROOT}/{title}");
            let entries = git::list_tree(&repo, title_dir.id)?;
            let heading = index_heading(&repo, &entries, &title_path)?;
            let mut subtitles: Vec<_> = entries.into_iter().filter(|e| e.is_dir).collect();
            subtitles.sort_by(|a, b| a.name.cmp(&b.name));

            let mut title_children = Vec::new();
            for sub_dir in subtitles {
                let subtitle = format!("{title}.{}", sub_dir.name);
                let sub_path = format!("{title_path}/{}", sub_dir.name);
                let entries = git::list_tree(&repo, sub_dir.id)?;
                let heading = index_heading(&repo, &entries, &sub_path)?;
                let mut files: Vec<_> = entries
                    .into_iter()
                    .filter(|e| !e.is_dir && e.name.ends_with(".xml") && e.name != "index.xml")
                    .collect();
                files.sort_by(|a, b| a.name.cmp(&b.name));

                let mut sub_children = Vec::new();
                for file in files {
                    let chapter = format!("{subtitle}.{}", file.name.trim_end_matches(".xml"));
                    let path = format!("{sub_path}/{}", file.name);
                    let xml = String::from_utf8(git::read_blob(&repo, file.id)?)
                        .with_context(|| format!("{path} is not UTF-8"))?;
                    lib.add_chapter(&chapter, &path, &xml)
                        .with_context(|| format!("parsing {path}"))?;
                    sub_children.push(chapter);
                }
                lib.containers.insert(
                    subtitle.clone(),
                    Container {
                        citation: subtitle.clone(),
                        level: Level::Subtitle,
                        heading,
                        children: sub_children,
                        path: format!("{sub_path}/index.xml"),
                    },
                );
                title_children.push(subtitle);
            }
            lib.containers.insert(
                title.clone(),
                Container {
                    citation: title.clone(),
                    level: Level::Title,
                    heading,
                    children: title_children,
                    path: format!("{title_path}/index.xml"),
                },
            );
            lib.titles.push(title);
        }
        Ok(lib)
    }

    fn add_chapter(&mut self, chapter: &str, path: &str, xml: &str) -> Result<()> {
        let doc = Document::parse(xml)?;
        let root = doc.root_element();
        let mut children = Vec::new();
        let mut authority = Vec::new();
        let mut history = Vec::new();

        for node in root.children().filter(Node::is_element) {
            match node.tag_name().name() {
                "section" => {
                    let num = child_text(node, "num").unwrap_or_default();
                    let reg_num = normalize_regulation_num(&num);
                    let citation = format!("{chapter}.{reg_num}");
                    let heading = child_text(node, "heading").unwrap_or_default();
                    let mut text = String::new();
                    render_children(node, 0, &mut text);
                    let text = text.trim_end().to_owned();
                    let searchable_original = format!("{heading}\n{text}");
                    self.regulations.insert(
                        citation.clone(),
                        Regulation {
                            citation: citation.clone(),
                            chapter: chapter.to_owned(),
                            heading,
                            text,
                            search_lower: searchable_original.to_ascii_lowercase(),
                            searchable_original,
                        },
                    );
                    self.order.push(citation.clone());
                    children.push(citation);
                }
                "annotations" => {
                    for a in node.children().filter(|n| n.has_tag_name("annotation")) {
                        let text = squash(&inline_text(a));
                        match a.attribute("type") {
                            Some("Authority") => authority.push(text),
                            _ => history.push(Annotation {
                                text,
                                cites: a
                                    .descendants()
                                    .filter_map(|c| c.attribute("path"))
                                    .map(str::to_owned)
                                    .collect(),
                            }),
                        }
                    }
                }
                _ => {}
            }
        }

        self.containers.insert(
            chapter.to_owned(),
            Container {
                citation: chapter.to_owned(),
                level: Level::Chapter,
                heading: child_text(root, "heading").unwrap_or_default(),
                children,
                path: path.to_owned(),
            },
        );
        self.chapters.insert(chapter.to_owned(), Chapter { authority, history });
        Ok(())
    }

    /// History notes that mention a particular regulation.
    pub fn regulation_history(&self, reg: &Regulation) -> Vec<&Annotation> {
        let Some(chapter) = self.chapters.get(&reg.chapter) else {
            return vec![];
        };
        // "10.09.01.06" -> "|10|09|01|.06"
        let mut parts = reg.citation.splitn(4, '.');
        let prefix = format!(
            "|{}|{}|{}|.{}",
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default()
        );
        chapter
            .history
            .iter()
            .filter(|a| {
                a.cites.iter().any(|c| {
                    c.strip_prefix(&prefix)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('|'))
                })
            })
            .collect()
    }

    pub fn search(&self, query: &str, within: Option<&str>, limit: usize) -> Vec<SearchHit<'_>> {
        let terms = query_terms(query);
        if terms.is_empty() {
            return vec![];
        }
        let mut hits: Vec<SearchHit<'_>> = self
            .order
            .iter()
            .filter(|c| within.is_none_or(|w| c.as_str() == w || c.starts_with(&format!("{w}."))))
            .filter_map(|c| self.regulations.get(c))
            .filter_map(|reg| {
                let mut score = 0;
                for term in &terms {
                    let count = reg.search_lower.matches(term.as_str()).count();
                    if count == 0 {
                        return None;
                    }
                    let heading_bonus = if reg.heading.to_ascii_lowercase().contains(term.as_str()) {
                        10
                    } else {
                        0
                    };
                    score += count.min(20) + heading_bonus;
                }
                let at = reg.search_lower.find(terms[0].as_str()).unwrap_or(0);
                Some(SearchHit { regulation: reg, score, snippet: snippet(&reg.searchable_original, at) })
            })
            .collect();
        // Stable sort keeps document order among equal scores.
        hits.sort_by(|a, b| b.score.cmp(&a.score));
        hits.truncate(limit);
        hits
    }
}

/// Parses citations such as `COMAR 10.09.01.03`, `10.09.01.03B(2)`, `13a.1.2`, or `10`.
/// Returns the normalized citation at the deepest level given.
pub fn parse_citation(input: &str) -> Result<String> {
    let s = input.trim();
    let s = s
        .strip_prefix("COMAR")
        .or_else(|| s.strip_prefix("comar"))
        .unwrap_or(s)
        .trim();
    let parts: Vec<&str> = s.split('.').map(str::trim).filter(|p| !p.is_empty()).collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(anyhow!(
            "'{input}' is not a COMAR citation; expected Title.Subtitle.Chapter.Regulation, e.g. 10.09.01.03"
        ));
    }
    let mut out = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let normalized = if i == 3 {
            // Drop any section designation after the regulation number: "03B(2)" -> "03".
            let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                return Err(anyhow!("'{part}' is not a regulation number"));
            }
            pad2(&digits)
        } else {
            let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
            let suffix = &part[digits.len()..];
            if digits.is_empty() || !suffix.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(anyhow!("'{part}' is not a valid citation component"));
            }
            format!("{}{}", pad2(&digits), suffix.to_ascii_uppercase())
        };
        out.push(normalized);
    }
    Ok(out.join("."))
}

fn pad2(digits: &str) -> String {
    if digits.len() < 2 { format!("0{digits}") } else { digits.to_owned() }
}

fn normalize_regulation_num(num: &str) -> String {
    let digits: String = num.trim().trim_start_matches('.').chars().take_while(char::is_ascii_digit).collect();
    pad2(&digits)
}

fn index_heading(repo: &gix::Repository, entries: &[git::DirEntry], path: &str) -> Result<String> {
    let Some(index) = entries.iter().find(|e| e.name == "index.xml") else {
        return Ok(String::new());
    };
    let xml = String::from_utf8(git::read_blob(repo, index.id)?)?;
    let doc = Document::parse(&xml).with_context(|| format!("parsing {path}/index.xml"))?;
    Ok(child_text(doc.root_element(), "heading").unwrap_or_default())
}

fn child_text(node: Node, tag: &str) -> Option<String> {
    node.children().find(|n| n.has_tag_name(tag)).map(|n| squash(&inline_text(n)))
}

/// All text beneath `node`, with `<br/>` turned into newlines.
fn inline_text(node: Node) -> String {
    let mut out = String::new();
    for d in node.descendants() {
        if d.is_text() {
            out.push_str(d.text().unwrap_or_default());
        } else if d.has_tag_name("br") {
            out.push('\n');
        }
    }
    out
}

/// Collapses runs of whitespace (but keeps explicit line breaks).
fn squash(s: &str) -> String {
    s.split('\n')
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders a section's body as indented plain text.
fn render_children(node: Node, depth: usize, out: &mut String) {
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "prefix" | "num" | "heading" | "annotations" => {}
            "para" => render_para(child, depth, out),
            "table" => render_table(child, depth, out),
            "section" => {
                let line = [child_text(child, "num"), child_text(child, "heading")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                push_line(out, depth, &line);
                render_children(child, depth + 1, out);
            }
            _ => {
                let text = squash(&inline_text(child));
                if !text.is_empty() {
                    push_line(out, depth, &text);
                }
            }
        }
    }
}

fn render_para(node: Node, depth: usize, out: &mut String) {
    let num = child_text(node, "num");
    let text = child_text(node, "text");
    let line = [num, text].into_iter().flatten().collect::<Vec<_>>().join(" ");
    if !line.is_empty() {
        push_line(out, depth, &line);
    }
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "num" | "text" => {}
            "para" => render_para(child, depth + 1, out),
            "table" => render_table(child, depth + 1, out),
            _ => {
                let t = squash(&inline_text(child));
                if !t.is_empty() {
                    push_line(out, depth + 1, &t);
                }
            }
        }
    }
}

fn render_table(node: Node, depth: usize, out: &mut String) {
    for row in node.descendants().filter(|n| n.has_tag_name("tr")) {
        let cells: Vec<String> = row
            .children()
            .filter(|c| c.has_tag_name("td") || c.has_tag_name("th"))
            .map(|c| squash(&inline_text(c)).replace('\n', " "))
            .collect();
        push_line(out, depth, &format!("| {} |", cells.join(" | ")));
    }
}

fn push_line(out: &mut String, depth: usize, text: &str) {
    for line in text.lines() {
        out.push_str(&"  ".repeat(depth));
        out.push_str(line);
        out.push('\n');
    }
}

/// Splits a query into lowercase terms; `"quoted phrases"` stay together.
fn query_terms(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    for (i, chunk) in query.split('"').enumerate() {
        let chunk = chunk.trim().to_ascii_lowercase();
        if chunk.is_empty() {
            continue;
        }
        if i % 2 == 1 {
            terms.push(chunk.split_whitespace().collect::<Vec<_>>().join(" "));
        } else {
            terms.extend(chunk.split_whitespace().map(str::to_owned));
        }
    }
    terms
}

fn snippet(text: &str, at: usize) -> String {
    let mut start = at.saturating_sub(120);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (at + 200).min(text.len());
    while !text.is_char_boundary(end) {
        end += 1;
    }
    let body = text[start..end].split_whitespace().collect::<Vec<_>>().join(" ");
    format!(
        "{}{}{}",
        if start > 0 { "…" } else { "" },
        body,
        if end < text.len() { "…" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn citations() {
        assert_eq!(parse_citation("COMAR 10.09.01.03").unwrap(), "10.09.01.03");
        assert_eq!(parse_citation("10.9.1.3B(2)").unwrap(), "10.09.01.03");
        assert_eq!(parse_citation("13a.01").unwrap(), "13A.01");
        assert_eq!(parse_citation("01.01.2020.04").unwrap(), "01.01.2020.04");
        assert_eq!(parse_citation(" 26 ").unwrap(), "26");
        assert!(parse_citation("ten").is_err());
        assert!(parse_citation("10.09.01.03.04").is_err());
    }

    #[test]
    fn terms() {
        assert_eq!(query_terms(r#"nurse "medical assistance"  Fees"#), ["nurse", "medical assistance", "fees"]);
    }

    #[test]
    fn renders_nested_paras() {
        let xml = r#"<container xmlns="https://open.law/schemas/library"><prefix>Chapter</prefix><num>01</num>
            <heading>Test Chapter</heading>
            <section><prefix>Regulation</prefix><num>.01</num><heading>Definitions.</heading>
              <para><num>A.</num><text>In this chapter:</text>
                <para><num>(1)</num><text>“Board” means <cite path="|10.27">the Board</cite>.</text></para>
              </para>
            </section>
            <annotations><annotation type="Authority">Some Article, §1</annotation>
              <annotation type="History"><cite path="|99|01|01|.01">Regulation .01</cite> adopted</annotation>
            </annotations></container>"#;
        let mut lib = Library {
            titles: vec![],
            containers: HashMap::new(),
            chapters: HashMap::new(),
            regulations: HashMap::new(),
            order: vec![],
        };
        lib.add_chapter("99.01.01", "x.xml", xml).unwrap();
        let reg = &lib.regulations["99.01.01.01"];
        assert_eq!(reg.heading, "Definitions.");
        assert_eq!(reg.text, "A. In this chapter:\n  (1) “Board” means the Board.");
        assert_eq!(lib.chapters["99.01.01"].authority, ["Some Article, §1"]);
        assert_eq!(lib.regulation_history(reg).len(), 1);
        assert_eq!(lib.search("board", None, 5).len(), 1);
        assert_eq!(lib.search("board zebra", None, 5).len(), 0);
    }
}

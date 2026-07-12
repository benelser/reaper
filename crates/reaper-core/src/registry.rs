//! Detection is DATA: the embedded TOML ruleset, PARSED not validated — an
//! unknown `safety`/`kind` is a load error, never a silent skip (§5). Three
//! detector shapes exist; 95% of rows are pure sibling-marker data.

use crate::model::{Candidate, DetectorId, EcosystemId, SafetyClass};
use camino::Utf8Path;
use serde::{Deserialize, Serialize};

/// How a sibling marker matches: an exact file name, or `*.ext`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Marker {
    Exact(String),
    Extension(String), // ".csproj" matches any *.csproj in the listing
}

impl Marker {
    fn parse(s: &str) -> Self {
        match s.strip_prefix('*') {
            Some(ext) => Marker::Extension(ext.to_string()),
            None => Marker::Exact(s.to_string()),
        }
    }
    /// A marker is "a sibling entry named X" — file OR dir: bundle markers
    /// like *.xcodeproj are directories (the coverage gate caught this).
    fn hits(&self, files: &[&str], dirs: &[&str]) -> bool {
        match self {
            Marker::Exact(name) => files.contains(&name.as_str()) || dirs.contains(&name.as_str()),
            Marker::Extension(ext) => files
                .iter()
                .chain(dirs.iter())
                .any(|f| f.ends_with(ext.as_str())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    /// Reclaim a child dir with this name — gated on a sibling marker when
    /// one is declared (`None` = the name alone is unambiguous, e.g.
    /// `__pycache__`).
    SiblingMarker {
        reclaim_dir: String,
        marker: Option<Marker>,
    },
    /// The listed dir ITSELF is a linked git worktree (`.git` FILE present;
    /// a `.git` DIR is someone's main checkout — never a candidate).
    GitWorktreeSelf,
    /// The listed dir declares ITSELF a cache (CACHEDIR.TAG present) —
    /// the Cache Directory Tagging Standard catch-all.
    CachedirTag,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detector {
    pub id: String,
    pub ecosystem: String,
    pub kind: DetectorKind,
    pub safety: SafetyClass,
}

/// One match: the candidate plus whether the walker must PRUNE. Reclaim
/// subdirs and self-declared caches prune (§6.3); a worktree candidate does
/// NOT (its inner bloat stays independently reapable).
pub struct Match {
    pub candidate: Candidate,
    pub prune: bool,
}

#[derive(Debug)]
pub struct RulesetError(pub String);

impl std::fmt::Display for RulesetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ruleset error: {}", self.0)
    }
}
impl std::error::Error for RulesetError {}

#[derive(Deserialize)]
struct RulesetFile {
    detector: Vec<DetectorRow>,
}

/// The TOML row — parsed into a typed `Detector` or rejected loudly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorRow {
    id: String,
    ecosystem: String,
    kind: Option<String>,
    reclaim_dir: Option<String>,
    marker: Option<String>,
    safety: String,
    regenerate: Option<String>,
}

pub struct Registry {
    detectors: Vec<Detector>,
}

impl Registry {
    /// The embedded ruleset — compiled in, parsed at startup, a load error
    /// is fatal (never a silent skip).
    pub fn embedded() -> Result<Self, RulesetError> {
        Self::from_toml(include_str!("../rules.toml"))
    }

    pub fn from_toml(text: &str) -> Result<Self, RulesetError> {
        let file: RulesetFile = toml::from_str(text).map_err(|e| RulesetError(e.to_string()))?;
        let mut detectors = Vec::with_capacity(file.detector.len());
        for row in file.detector {
            let safety = match row.safety.as_str() {
                "regenerable" => SafetyClass::Regenerable {
                    regenerate_hint: row.regenerate.clone(),
                },
                "git_worktree" => SafetyClass::GitWorktree,
                "package_cache" => SafetyClass::PackageCache,
                other => {
                    return Err(RulesetError(format!(
                        "detector {}: unknown safety {other:?}",
                        row.id
                    )))
                }
            };
            let kind = match row.kind.as_deref() {
                None => DetectorKind::SiblingMarker {
                    reclaim_dir: row.reclaim_dir.ok_or_else(|| {
                        RulesetError(format!("detector {}: reclaim_dir required", row.id))
                    })?,
                    marker: row.marker.as_deref().map(Marker::parse),
                },
                Some("git_worktree") => DetectorKind::GitWorktreeSelf,
                Some("cachedir_tag") => DetectorKind::CachedirTag,
                Some(other) => {
                    return Err(RulesetError(format!(
                        "detector {}: unknown kind {other:?}",
                        row.id
                    )))
                }
            };
            detectors.push(Detector {
                id: row.id,
                ecosystem: row.ecosystem,
                kind,
                safety,
            });
        }
        Ok(Self { detectors })
    }

    /// A registry that matches nothing (bench baseline: full walk, no prune).
    pub fn empty() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// The active rows, for `reaper rules` (audit).
    pub fn detectors(&self) -> &[Detector] {
        &self.detectors
    }

    /// Match against ONE directory's listing, split by entry kind (both come
    /// free from the walker's dirent batch — zero extra syscalls). Ruleset
    /// order is precedence: first match per path wins (§13).
    pub fn match_listing(&self, dir: &Utf8Path, files: &[&str], dirs: &[&str]) -> Vec<Match> {
        let mut out: Vec<Match> = Vec::new();
        let claim = |m: Match, out: &mut Vec<Match>| {
            if !out.iter().any(|o| o.candidate.path == m.candidate.path) {
                out.push(m);
            }
        };
        for d in &self.detectors {
            match &d.kind {
                DetectorKind::SiblingMarker {
                    reclaim_dir,
                    marker,
                } => {
                    let marker_ok = marker.as_ref().is_none_or(|m| m.hits(files, dirs));
                    if marker_ok && dirs.contains(&reclaim_dir.as_str()) {
                        claim(
                            Match {
                                candidate: self.candidate(d, dir.join(reclaim_dir)),
                                prune: true,
                            },
                            &mut out,
                        );
                    }
                }
                DetectorKind::GitWorktreeSelf => {
                    if files.contains(&".git") {
                        claim(
                            Match {
                                candidate: self.candidate(d, dir.to_owned()),
                                prune: false,
                            },
                            &mut out,
                        );
                    }
                }
                DetectorKind::CachedirTag => {
                    if files.contains(&"CACHEDIR.TAG") {
                        claim(
                            Match {
                                candidate: self.candidate(d, dir.to_owned()),
                                prune: true,
                            },
                            &mut out,
                        );
                    }
                }
            }
        }
        out
    }

    fn candidate(&self, d: &Detector, path: camino::Utf8PathBuf) -> Candidate {
        Candidate {
            path,
            ecosystem: EcosystemId(d.ecosystem.clone()),
            detector: DetectorId(d.id.clone()),
            safety_class: d.safety.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    #[test]
    fn embedded_ruleset_parses_and_covers_the_bar() {
        let reg = Registry::embedded().expect("embedded ruleset must always load");
        assert!(
            reg.detectors().len() >= 15,
            "launch coverage bar: top ~15 ecosystems"
        );
    }

    #[test]
    fn unknown_safety_or_kind_is_a_load_error_never_a_skip() {
        let bad = r#"[[detector]]
id = "x"
ecosystem = "x"
reclaim_dir = "y"
safety = "yolo""#;
        assert!(Registry::from_toml(bad).is_err());
        let bad_kind = r#"[[detector]]
id = "x"
ecosystem = "x"
kind = "telepathy"
safety = "regenerable""#;
        assert!(Registry::from_toml(bad_kind).is_err());
    }

    #[test]
    fn rust_target_fires_only_with_sibling_marker() {
        let reg = Registry::embedded().unwrap();
        let dir = Utf8PathBuf::from("/w/proj");
        let hit = reg.match_listing(&dir, &["Cargo.toml"], &["src", "target"]);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].candidate.path, dir.join("target"));
        assert!(hit[0].prune);
        assert!(reg.match_listing(&dir, &[], &["src", "target"]).is_empty());
    }

    #[test]
    fn first_match_wins_when_two_rows_claim_one_path() {
        // Both Cargo.toml and pom.xml present: rust-target is first in the
        // ruleset, so `target` is claimed once, as rust.
        let reg = Registry::embedded().unwrap();
        let dir = Utf8PathBuf::from("/w/poly");
        let hits = reg.match_listing(&dir, &["Cargo.toml", "pom.xml"], &["target"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].candidate.detector, DetectorId("rust-target".into()));
    }

    #[test]
    fn extension_markers_and_markerless_rows_fire() {
        let reg = Registry::embedded().unwrap();
        let dir = Utf8PathBuf::from("/w/app");
        // *.csproj extension marker
        let hits = reg.match_listing(&dir, &["App.csproj"], &["bin", "obj"]);
        assert_eq!(hits.len(), 2);
        // markerless __pycache__
        let hits = reg.match_listing(&dir, &[], &["__pycache__"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].candidate.ecosystem, EcosystemId("python".into()));
    }

    #[test]
    fn cachedir_tag_claims_self_and_prunes() {
        let reg = Registry::embedded().unwrap();
        let dir = Utf8PathBuf::from("/w/somecache/v2");
        let hits = reg.match_listing(&dir, &["CACHEDIR.TAG", "data.bin"], &["gen"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].candidate.path, dir);
        assert!(hits[0].prune, "a self-declared cache is never descended");
    }

    #[test]
    fn git_file_marks_a_worktree_but_git_dir_never_does() {
        let reg = Registry::embedded().unwrap();
        let dir = Utf8PathBuf::from("/w/repo/.wt/feature");
        let hit = reg.match_listing(&dir, &[".git", "README.md"], &["src"]);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].candidate.safety_class, SafetyClass::GitWorktree);
        assert!(!hit[0].prune);
        assert!(reg
            .match_listing(&dir, &["README.md"], &[".git", "src"])
            .is_empty());
    }
}

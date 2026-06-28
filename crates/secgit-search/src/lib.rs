//! # secgit-search
//!
//! In-CVM code search. The inverted index (token -> document postings) is persisted
//! through [`secgit_store::EncryptedStore`], so the index — which would otherwise leak the
//! vocabulary of private code — is **ciphertext on the operator's disk**, encrypted under
//! the same per-repo DEK as the code itself. Per-repo isolation is automatic: each repo's
//! postings live under its own store namespace/DEK.
//!
//! The index stores only postings (token -> file paths). Line-level results are produced at
//! query time by fetching candidate blobs through a caller-supplied content function, so no
//! second plaintext copy of the code is kept. **Access control is enforced at the call
//! site**: the server only searches repos the requesting user may read.

use secgit_store::EncryptedStore;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SearchError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

pub type Result<T> = core::result::Result<T, SearchError>;

/// A single search result line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub repo_id: String,
    pub path: String,
    pub line: usize,
    pub snippet: String,
}

/// Search index over a borrowed encrypted store.
pub struct SearchIndex<'a> {
    store: &'a EncryptedStore,
}

impl<'a> SearchIndex<'a> {
    pub fn new(store: &'a EncryptedStore) -> Self {
        Self { store }
    }

    /// Index (or re-index) a document. Re-indexing replaces the document's postings.
    pub fn index_document(&self, repo_id: &str, path: &str, content: &str) -> Result<()> {
        self.remove_document(repo_id, path)?;
        let tokens = tokenize(content);
        for tok in &tokens {
            let key = tok_key(tok);
            let mut postings: Vec<String> = self.get(repo_id, &key)?.unwrap_or_default();
            if !postings.iter().any(|p| p == path) {
                postings.push(path.to_string());
                self.put(repo_id, &key, &postings)?;
            }
        }
        // Remember which tokens this doc contributed, for clean removal later.
        let doc_tokens: Vec<String> = tokens.into_iter().collect();
        self.put(repo_id, &doc_key(path), &doc_tokens)?;
        let mut docs: Vec<String> = self.get(repo_id, "docs")?.unwrap_or_default();
        if !docs.iter().any(|p| p == path) {
            docs.push(path.to_string());
            self.put(repo_id, "docs", &docs)?;
        }
        Ok(())
    }

    /// Remove a document from the index.
    pub fn remove_document(&self, repo_id: &str, path: &str) -> Result<()> {
        let Some(doc_tokens) = self.get::<Vec<String>>(repo_id, &doc_key(path))? else {
            return Ok(());
        };
        for tok in doc_tokens {
            let key = tok_key(&tok);
            if let Some(mut postings) = self.get::<Vec<String>>(repo_id, &key)? {
                postings.retain(|p| p != path);
                self.put(repo_id, &key, &postings)?;
            }
        }
        self.store.delete(repo_id, &doc_key(path)).map_err(stor)?;
        let mut docs: Vec<String> = self.get(repo_id, "docs")?.unwrap_or_default();
        docs.retain(|p| p != path);
        self.put(repo_id, "docs", &docs)?;
        Ok(())
    }

    /// List indexed document paths for a repo.
    pub fn documents(&self, repo_id: &str) -> Result<Vec<String>> {
        Ok(self.get(repo_id, "docs")?.unwrap_or_default())
    }

    /// Search a single repo. `fetch` returns the current content of a path (for line hits).
    pub fn search_repo<F>(
        &self,
        repo_id: &str,
        query: &str,
        max_hits: usize,
        fetch: &F,
    ) -> Result<Vec<SearchHit>>
    where
        F: Fn(&str, &str) -> Option<String>,
    {
        let terms = tokenize(query);
        if terms.is_empty() {
            return Ok(vec![]);
        }
        // Candidate documents = intersection of postings for each term.
        let mut candidates: Option<BTreeSet<String>> = None;
        for term in &terms {
            let postings: Vec<String> = self.get(repo_id, &tok_key(term))?.unwrap_or_default();
            let set: BTreeSet<String> = postings.into_iter().collect();
            candidates = Some(match candidates {
                None => set,
                Some(cur) => cur.intersection(&set).cloned().collect(),
            });
            if candidates.as_ref().map(|c| c.is_empty()).unwrap_or(false) {
                return Ok(vec![]);
            }
        }
        let candidates = candidates.unwrap_or_default();

        let needle_terms: Vec<String> = terms.into_iter().collect();
        let mut hits = vec![];
        for path in candidates {
            let Some(content) = fetch(repo_id, &path) else {
                continue;
            };
            for (i, line) in content.lines().enumerate() {
                let lower = line.to_lowercase();
                if needle_terms.iter().all(|t| lower.contains(t.as_str())) {
                    hits.push(SearchHit {
                        repo_id: repo_id.to_string(),
                        path: path.clone(),
                        line: i + 1,
                        snippet: line.trim().chars().take(200).collect(),
                    });
                    if hits.len() >= max_hits {
                        return Ok(hits);
                    }
                }
            }
        }
        Ok(hits)
    }

    fn put<T: Serialize>(&self, repo_id: &str, key: &str, v: &T) -> Result<()> {
        let bytes = serde_json::to_vec(v).map_err(|e| SearchError::Serde(e.to_string()))?;
        self.store.put(repo_id, key, &bytes).map_err(stor)
    }
    fn get<T: DeserializeOwned>(&self, repo_id: &str, key: &str) -> Result<Option<T>> {
        match self.store.get(repo_id, key).map_err(stor)? {
            Some(b) => Ok(Some(
                serde_json::from_slice(&b).map_err(|e| SearchError::Serde(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }
}

fn stor(e: secgit_store::StoreError) -> SearchError {
    SearchError::Storage(e.to_string())
}

fn tok_key(tok: &str) -> String {
    format!("tok/{tok}")
}
fn doc_key(path: &str) -> String {
    format!("doc/{path}")
}

/// Tokenize into lowercase `[a-z0-9_]+` tokens of length >= 2 (deduplicated, sorted).
fn tokenize(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c.to_ascii_lowercase());
        } else if cur.len() >= 2 {
            out.insert(std::mem::take(&mut cur));
        } else {
            cur.clear();
        }
    }
    if cur.len() >= 2 {
        out.insert(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use secgit_crypto::aead::SymKey;
    use std::collections::HashMap;

    fn store(tag: &str) -> (EncryptedStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("secgit-search-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (
            EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap(),
            dir,
        )
    }

    #[test]
    fn indexes_and_finds_lines() {
        let (s, dir) = store("find");
        let idx = SearchIndex::new(&s);
        let main_rs =
            "fn main() {\n    let token = compute_token();\n    println!(\"{}\", token);\n}\n";
        let util_rs = "pub fn helper() -> u32 { 42 }\n";
        idx.index_document("repo", "src/main.rs", main_rs).unwrap();
        idx.index_document("repo", "src/util.rs", util_rs).unwrap();

        let content: HashMap<(&str, &str), &str> = [
            (("repo", "src/main.rs"), main_rs),
            (("repo", "src/util.rs"), util_rs),
        ]
        .into();
        let fetch = |r: &str, p: &str| content.get(&(r, p)).map(|s| s.to_string());

        let hits = idx.search_repo("repo", "token", 50, &fetch).unwrap();
        // Two lines in main.rs mention "token".
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.path == "src/main.rs"));
        assert_eq!(hits[0].line, 2);

        // Multi-term query requires all terms present in a candidate doc.
        let none = idx.search_repo("repo", "token helper", 50, &fetch).unwrap();
        assert!(none.is_empty(), "no single doc has both tokens");

        let helper = idx.search_repo("repo", "helper", 50, &fetch).unwrap();
        assert_eq!(helper.len(), 1);
        assert_eq!(helper[0].path, "src/util.rs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reindex_and_remove_update_postings() {
        let (s, dir) = store("reindex");
        let idx = SearchIndex::new(&s);
        idx.index_document("repo", "a.txt", "alpha beta").unwrap();
        assert_eq!(idx.documents("repo").unwrap().len(), 1);

        // Re-index with different content; old token must no longer match.
        idx.index_document("repo", "a.txt", "gamma delta").unwrap();
        let fetch = |_: &str, _: &str| Some("gamma delta".to_string());
        assert!(idx
            .search_repo("repo", "alpha", 10, &fetch)
            .unwrap()
            .is_empty());
        assert_eq!(
            idx.search_repo("repo", "gamma", 10, &fetch).unwrap().len(),
            1
        );

        idx.remove_document("repo", "a.txt").unwrap();
        assert!(idx.documents("repo").unwrap().is_empty());
        assert!(idx
            .search_repo("repo", "gamma", 10, &fetch)
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_is_ciphertext_on_disk() {
        use secgit_leaktest::assert_dir_ciphertext_nonempty;
        // A contiguous lowercase token so it is stored verbatim as an index token (would
        // appear on disk if the index were not encrypted).
        let symbol = format!("secretsymbol{}", std::process::id());
        let dir = std::env::temp_dir().join(format!("secgit-search-leak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = EncryptedStore::open(&dir, SymKey::generate().unwrap()).unwrap();
            let idx = SearchIndex::new(&s);
            idx.index_document("repo", "f.rs", &format!("let {symbol} = 1;"))
                .unwrap();
        }
        assert_dir_ciphertext_nonempty(&dir, &[symbol.as_bytes()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

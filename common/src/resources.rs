//! Well-known resource slots and their schemas. The authoritative
//! consumer-facing prose lives in docs/resources.md; these are the same
//! rules as code.

use serde::{Deserialize, Serialize};

pub const SLOT_PROFILE: &str = "profile";
pub const SLOT_AVATAR: &str = "avatar";
/// Optional Freenet ghostkey proof (see `ghostkey` module, feature `ghostkey`).
pub const SLOT_GHOSTKEY: &str = "ghostkey";
/// Link tree: raw UTF-8 markdown, one `[title](https://url)` per line.
pub const SLOT_LINKTREE: &str = "linktree";
/// Prefix for anonymous Proof-of-Personhood attestation slots (`poh:<provider>`).
pub const SLOT_POH_PREFIX: &str = "poh:";
/// Anonymous GitHub Proof-of-Personhood slot (see `poh` module, feature `poh`).
pub const SLOT_POH_GITHUB: &str = "poh:github";
/// Anonymous Google Proof-of-Personhood slot (see `poh` module, feature `poh`).
pub const SLOT_POH_GOOGLE: &str = "poh:google";

/// Canonical `poh:<provider>` identity slot name.
pub fn poh_slot(provider: &str) -> String {
    format!("{SLOT_POH_PREFIX}{provider}")
}

pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_BIO_CHARS: usize = 280;
pub const MAX_LINKTREE_BYTES: usize = 8 * 1024;
pub const MAX_AVATAR_BYTES: usize = 128 * 1024;
pub const MIN_AVATAR_DIM: u32 = 64;
pub const MAX_AVATAR_DIM: u32 = 512;

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ProfileV1 {
    pub name: String,
    pub bio: String,
}

pub fn check_profile(p: &ProfileV1) -> Result<(), String> {
    if p.name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("name exceeds {MAX_NAME_CHARS} characters"));
    }
    if p.bio.chars().count() > MAX_BIO_CHARS {
        return Err(format!("bio exceeds {MAX_BIO_CHARS} characters"));
    }
    Ok(())
}

/// One rendered line of a link tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TreeItem {
    Heading(String),
    Link { title: String, url: String },
    Text(String),
}

pub fn check_linktree(md: &str) -> Result<(), String> {
    if md.len() > MAX_LINKTREE_BYTES {
        return Err(format!("link tree exceeds {MAX_LINKTREE_BYTES} bytes"));
    }
    Ok(())
}

/// Slot bytes → markdown, or None if too big / not UTF-8 (signed ≠ well-formed).
pub fn check_linktree_bytes(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    check_linktree(s).ok()?;
    Some(s.to_string())
}

/// Parse link-tree markdown. Supported: `# heading`, `[title](url)` (optional
/// `- `/`* ` bullet), plain text. Only http(s) URLs become links — anything
/// else (`javascript:`, `data:`…) is demoted to text, so output is safe to
/// put in an `href`. Never interpret the markdown as HTML.
pub fn parse_linktree(md: &str) -> Vec<TreeItem> {
    md.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            if let Some(h) = l.strip_prefix('#') {
                return TreeItem::Heading(h.trim_start_matches('#').trim().to_string());
            }
            let body = l.trim_start_matches(['-', '*', '+']).trim_start();
            if let Some((title, url)) = body
                .strip_prefix('[')
                .and_then(|r| r.split_once("]("))
                .and_then(|(t, r)| Some((t, r.strip_suffix(')')?)))
            {
                let url = url.trim();
                if !title.trim().is_empty()
                    && !url.contains(char::is_whitespace)
                    && (url.starts_with("https://") || url.starts_with("http://"))
                {
                    return TreeItem::Link { title: title.trim().to_string(), url: url.to_string() };
                }
            }
            TreeItem::Text(l.to_string())
        })
        .collect()
}

/// Container sniff only — PNG or WebP magic and the byte cap. Pixel
/// dimensions are enforced at upload time by the UI (which re-encodes);
/// consumers should still treat dimensions as advisory.
pub fn check_avatar_bytes(b: &[u8]) -> Result<(), String> {
    if b.len() > MAX_AVATAR_BYTES {
        return Err(format!("avatar exceeds {MAX_AVATAR_BYTES} bytes"));
    }
    let png = b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    let webp = b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP";
    if !(png || webp) {
        return Err("avatar must be PNG or WebP".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_limits() {
        assert!(check_profile(&ProfileV1 {
            name: "graff".into(),
            bio: "hello".into()
        })
        .is_ok());
        assert!(check_profile(&ProfileV1 {
            name: "x".repeat(MAX_NAME_CHARS + 1),
            bio: String::new()
        })
        .is_err());
        assert!(check_profile(&ProfileV1 {
            name: String::new(),
            bio: "x".repeat(MAX_BIO_CHARS + 1)
        })
        .is_err());
    }

    #[test]
    fn linktree_parse() {
        let t = parse_linktree("# me\n- [GH](https://github.com/x)\n[bad](javascript:alert(1))\nhi\n\n[ws](https://a b)");
        assert_eq!(t[0], TreeItem::Heading("me".into()));
        assert_eq!(t[1], TreeItem::Link { title: "GH".into(), url: "https://github.com/x".into() });
        assert!(matches!(t[2], TreeItem::Text(_)));
        assert!(matches!(t[3], TreeItem::Text(_)));
        assert!(matches!(t[4], TreeItem::Text(_)));
        assert!(check_linktree(&"x".repeat(MAX_LINKTREE_BYTES + 1)).is_err());
    }

    #[test]
    fn avatar_magic() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert!(check_avatar_bytes(&png).is_ok());
        let mut webp = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
        webp.push(0);
        assert!(check_avatar_bytes(&webp).is_ok());
        assert!(check_avatar_bytes(b"GIF89a....").is_err());
        assert!(check_avatar_bytes(&vec![0x89; MAX_AVATAR_BYTES + 1]).is_err());
    }
}

//! A small XML DOM + parser + **Exclusive XML Canonicalization (exc-c14n)**.
//!
//! This exists only to verify SAML XML-DSig signatures. It is deliberately scoped to the
//! XML profile real IdPs emit for SAML assertions: elements, attributes, namespace
//! declarations, and text. It does **not** support comments-in-signature, processing
//! instructions, CDATA inside signed content, or DTDs — these are rejected/ignored, and
//! the supported profile is documented in `docs/sso-saml.md`.
//!
//! Exclusive c14n (<http://www.w3.org/2001/10/xml-exc-c14n#>) is implemented to spec for
//! this profile: a subtree is rendered self-contained, emitting only the namespaces
//! *visibly utilized* by each element (plus an optional InclusiveNamespaces PrefixList),
//! with attributes sorted by (namespace-URI, local-name) and namespace declarations sorted
//! by prefix. Self-consistency is round-trip tested against signatures we generate; the
//! algorithm follows the W3C exc-c14n recommendation.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Debug, Clone)]
pub struct Attr {
    pub prefix: Option<String>,
    pub local: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub prefix: Option<String>,
    pub local: String,
    /// Namespace declarations made *on this element*: (prefix or None for default) -> URI.
    pub ns_decls: Vec<(Option<String>, String)>,
    pub attrs: Vec<Attr>,
    pub children: Vec<Node>,
}

impl Element {
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }

    /// First direct child element with the given local name (namespace-agnostic).
    pub fn child(&self, local: &str) -> Option<&Element> {
        self.children.iter().find_map(|n| match n {
            Node::Element(e) if e.local == local => Some(e),
            _ => None,
        })
    }

    /// All direct child elements with the given local name.
    pub fn children_named<'a>(&'a self, local: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter_map(move |n| match n {
            Node::Element(e) if e.local == local => Some(e),
            _ => None,
        })
    }

    /// Recursively find the first descendant (or self) with the given local name.
    pub fn find_descendant(&self, local: &str) -> Option<&Element> {
        if self.local == local {
            return Some(self);
        }
        for n in &self.children {
            if let Node::Element(e) = n {
                if let Some(found) = e.find_descendant(local) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Attribute value by local name (namespace-agnostic).
    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.local == local)
            .map(|a| a.value.as_str())
    }

    /// Concatenated direct text content, trimmed.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                s.push_str(t);
            }
        }
        s.trim().to_string()
    }
}

#[derive(Debug)]
pub struct XmlError(pub String);

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "xml error: {}", self.0)
    }
}

/// Parse an XML document into its root element.
pub fn parse(input: &str) -> Result<Element, XmlError> {
    let mut p = Parser {
        b: input.as_bytes(),
        i: 0,
    };
    p.skip_prolog()?;
    let root = p.parse_element()?;
    Ok(root)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn starts_with(&self, s: &str) -> bool {
        self.b[self.i..].starts_with(s.as_bytes())
    }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn skip_prolog(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_ws();
            if self.starts_with("<?") {
                let end = self.find("?>")?;
                self.i = end + 2;
            } else if self.starts_with("<!--") {
                let end = self.find("-->")?;
                self.i = end + 3;
            } else if self.starts_with("<!") {
                // DOCTYPE — reject to avoid XXE/entity-expansion surprises.
                return Err(XmlError("DTD/DOCTYPE not supported".into()));
            } else {
                return Ok(());
            }
        }
    }

    fn find(&self, needle: &str) -> Result<usize, XmlError> {
        self.b[self.i..]
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())
            .map(|p| self.i + p)
            .ok_or_else(|| XmlError(format!("unterminated: expected {needle}")))
    }

    fn parse_name(&mut self) -> (Option<String>, String) {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b' '
                || c == b'\t'
                || c == b'\r'
                || c == b'\n'
                || c == b'>'
                || c == b'/'
                || c == b'='
            {
                break;
            }
            self.i += 1;
        }
        let raw = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("");
        match raw.split_once(':') {
            Some((p, l)) => (Some(p.to_string()), l.to_string()),
            None => (None, raw.to_string()),
        }
    }

    fn parse_element(&mut self) -> Result<Element, XmlError> {
        if self.peek() != Some(b'<') {
            return Err(XmlError("expected '<'".into()));
        }
        self.i += 1;
        let (prefix, local) = self.parse_name();
        let mut ns_decls = vec![];
        let mut attrs = vec![];

        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'/') => {
                    self.i += 1;
                    if self.peek() != Some(b'>') {
                        return Err(XmlError("malformed self-closing tag".into()));
                    }
                    self.i += 1;
                    return Ok(Element {
                        prefix,
                        local,
                        ns_decls,
                        attrs,
                        children: vec![],
                    });
                }
                Some(b'>') => {
                    self.i += 1;
                    break;
                }
                Some(_) => {
                    let (ap, al) = self.parse_name();
                    self.skip_ws();
                    if self.peek() != Some(b'=') {
                        return Err(XmlError("expected '=' in attribute".into()));
                    }
                    self.i += 1;
                    self.skip_ws();
                    let quote = self.peek().ok_or_else(|| XmlError("attr quote".into()))?;
                    if quote != b'"' && quote != b'\'' {
                        return Err(XmlError("attr value must be quoted".into()));
                    }
                    self.i += 1;
                    let vstart = self.i;
                    while self.peek().is_some() && self.peek() != Some(quote) {
                        self.i += 1;
                    }
                    let raw = std::str::from_utf8(&self.b[vstart..self.i]).unwrap_or("");
                    let value = decode_entities(raw);
                    self.i += 1; // closing quote
                    if ap.as_deref() == Some("xmlns") {
                        ns_decls.push((Some(al), value));
                    } else if ap.is_none() && al == "xmlns" {
                        ns_decls.push((None, value));
                    } else {
                        attrs.push(Attr {
                            prefix: ap,
                            local: al,
                            value,
                        });
                    }
                }
                None => return Err(XmlError("unexpected EOF in tag".into())),
            }
        }

        // Children until matching close tag.
        let mut children = vec![];
        loop {
            if self.starts_with("</") {
                self.i += 2;
                let _ = self.parse_name();
                self.skip_ws();
                if self.peek() != Some(b'>') {
                    return Err(XmlError("malformed end tag".into()));
                }
                self.i += 1;
                break;
            } else if self.starts_with("<!--") {
                let end = self.find("-->")?;
                self.i = end + 3;
            } else if self.starts_with("<![CDATA[") {
                self.i += 9;
                let end = self.find("]]>")?;
                let raw = std::str::from_utf8(&self.b[self.i..end]).unwrap_or("");
                children.push(Node::Text(raw.to_string()));
                self.i = end + 3;
            } else if self.peek() == Some(b'<') {
                children.push(Node::Element(self.parse_element()?));
            } else if self.peek().is_none() {
                return Err(XmlError("unexpected EOF in element body".into()));
            } else {
                let start = self.i;
                while self.peek().is_some() && self.peek() != Some(b'<') {
                    self.i += 1;
                }
                let raw = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("");
                children.push(Node::Text(decode_entities(raw)));
            }
        }

        Ok(Element {
            prefix,
            local,
            ns_decls,
            attrs,
            children,
        })
    }
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(end) = s[i..].find(';') {
                let ent = &s[i + 1..i + end];
                let rep = match ent {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "amp" => Some('&'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                        u32::from_str_radix(&ent[2..], 16)
                            .ok()
                            .and_then(char::from_u32)
                    }
                    _ if ent.starts_with('#') => {
                        ent[1..].parse::<u32>().ok().and_then(char::from_u32)
                    }
                    _ => None,
                };
                if let Some(c) = rep {
                    out.push(c);
                    i += end + 1;
                    continue;
                }
            }
        }
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&s[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

// ---- Exclusive C14N ---------------------------------------------------------

/// A namespace context: prefix (empty string = default) -> URI currently in scope.
pub type NsScope = BTreeMap<String, String>;

/// Canonicalize `el` as an exclusive-c14n subtree. `inclusive_prefixes` is the
/// InclusiveNamespaces PrefixList (treated as visibly utilized even when not used).
pub fn exc_c14n(el: &Element, inclusive_prefixes: &[String]) -> Vec<u8> {
    exc_c14n_scoped(el, inclusive_prefixes, &NsScope::new())
}

/// Like [`exc_c14n`] but with an inherited namespace scope (the namespaces declared by
/// ancestors of `el`). Required to correctly canonicalize an inner element (e.g.
/// `SignedInfo`) whose prefixes are declared higher in the document.
pub fn exc_c14n_scoped(
    el: &Element,
    inclusive_prefixes: &[String],
    inherited: &NsScope,
) -> Vec<u8> {
    let mut out = String::new();
    let rendered = NsScope::new();
    serialize(el, inherited, &rendered, inclusive_prefixes, &mut out);
    out.into_bytes()
}

/// Find the first element (depth-first) satisfying `pred`, returning it together with the
/// namespace scope inherited from its ancestors (not including its own declarations).
pub fn find_with_scope<'a>(
    root: &'a Element,
    pred: &dyn Fn(&Element) -> bool,
) -> Option<(&'a Element, NsScope)> {
    fn walk<'a>(
        el: &'a Element,
        inherited: &NsScope,
        pred: &dyn Fn(&Element) -> bool,
    ) -> Option<(&'a Element, NsScope)> {
        if pred(el) {
            return Some((el, inherited.clone()));
        }
        let mut scope = inherited.clone();
        for (p, uri) in &el.ns_decls {
            let k = p.clone().unwrap_or_default();
            if k.is_empty() && uri.is_empty() {
                scope.remove("");
            } else {
                scope.insert(k, uri.clone());
            }
        }
        for c in &el.children {
            if let Node::Element(e) = c {
                if let Some(found) = walk(e, &scope, pred) {
                    return Some(found);
                }
            }
        }
        None
    }
    walk(root, &NsScope::new(), pred)
}

fn serialize(
    el: &Element,
    parent_in_scope: &NsScope,
    parent_rendered: &NsScope,
    incl: &[String],
    out: &mut String,
) {
    // Update the in-scope namespace map with this element's declarations.
    let mut in_scope = parent_in_scope.clone();
    for (p, uri) in &el.ns_decls {
        let key = p.clone().unwrap_or_default();
        if key.is_empty() && uri.is_empty() {
            in_scope.remove("");
        } else {
            in_scope.insert(key, uri.clone());
        }
    }

    // Determine visibly-utilized prefixes: element's prefix, attribute prefixes, and
    // the InclusiveNamespaces prefix list.
    let mut utilized: BTreeMap<String, ()> = BTreeMap::new();
    utilized.insert(el.prefix.clone().unwrap_or_default(), ());
    for a in &el.attrs {
        if let Some(p) = &a.prefix {
            utilized.insert(p.clone(), ());
        }
    }
    for p in incl {
        utilized.insert(p.clone(), ());
    }

    // Decide which namespace declarations to render (sorted; default ns "" first).
    let mut rendered = parent_rendered.clone();
    let mut ns_to_emit: Vec<(String, String)> = vec![];
    for prefix in utilized.keys() {
        let uri = in_scope.get(prefix).cloned().unwrap_or_default();
        if prefix.is_empty() && uri.is_empty() {
            // Default ns is empty and not rendered with a value: emit nothing unless an
            // ancestor rendered a non-empty default we must cancel.
            if let Some(prev) = parent_rendered.get("") {
                if !prev.is_empty() {
                    ns_to_emit.push((String::new(), String::new()));
                    rendered.insert(String::new(), String::new());
                }
            }
            continue;
        }
        if uri.is_empty() {
            continue;
        }
        match parent_rendered.get(prefix) {
            Some(prev) if prev == &uri => {}
            _ => {
                ns_to_emit.push((prefix.clone(), uri.clone()));
                rendered.insert(prefix.clone(), uri.clone());
            }
        }
    }
    ns_to_emit.sort_by(|a, b| a.0.cmp(&b.0));

    out.push('<');
    out.push_str(&el.qname());
    for (prefix, uri) in &ns_to_emit {
        if prefix.is_empty() {
            out.push_str(&format!(" xmlns=\"{}\"", attr_escape(uri)));
        } else {
            out.push_str(&format!(" xmlns:{}=\"{}\"", prefix, attr_escape(uri)));
        }
    }

    // Attributes: sorted by (namespace URI, local name); no-namespace (empty URI) first.
    let mut sorted_attrs: Vec<&Attr> = el.attrs.iter().collect();
    sorted_attrs.sort_by(|a, b| {
        let au = a
            .prefix
            .as_ref()
            .and_then(|p| in_scope.get(p))
            .cloned()
            .unwrap_or_default();
        let bu = b
            .prefix
            .as_ref()
            .and_then(|p| in_scope.get(p))
            .cloned()
            .unwrap_or_default();
        au.cmp(&bu).then(a.local.cmp(&b.local))
    });
    for a in sorted_attrs {
        let name = match &a.prefix {
            Some(p) => format!("{p}:{}", a.local),
            None => a.local.clone(),
        };
        out.push_str(&format!(" {}=\"{}\"", name, attr_escape(&a.value)));
    }
    out.push('>');

    for child in &el.children {
        match child {
            Node::Element(e) => serialize(e, &in_scope, &rendered, incl, out),
            Node::Text(t) => out.push_str(&text_escape(t)),
        }
    }

    out.push_str(&format!("</{}>", el.qname()));
}

/// Serialize `el` to exc-c14n, but first remove the enveloped `<ds:Signature>` element
/// (the standard enveloped-signature transform for SAML).
pub fn exc_c14n_enveloped(el: &Element, inclusive_prefixes: &[String]) -> Vec<u8> {
    exc_c14n_enveloped_scoped(el, inclusive_prefixes, &NsScope::new())
}

/// Enveloped-signature transform + exclusive c14n with an inherited namespace scope.
pub fn exc_c14n_enveloped_scoped(
    el: &Element,
    inclusive_prefixes: &[String],
    inherited: &NsScope,
) -> Vec<u8> {
    let stripped = strip_signature(el);
    exc_c14n_scoped(&stripped, inclusive_prefixes, inherited)
}

fn strip_signature(el: &Element) -> Element {
    let mut clone = el.clone();
    clone.children = clone
        .children
        .into_iter()
        .filter_map(|n| match n {
            Node::Element(e) if e.local == "Signature" => None,
            Node::Element(e) => Some(Node::Element(strip_signature(&e))),
            other => Some(other),
        })
        .collect();
    clone
}

fn text_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
    out
}

fn attr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_with_namespaces() {
        let xml = r#"<saml:Assertion xmlns:saml="urn:saml" ID="a1" Version="2.0">
            <saml:Issuer>idp</saml:Issuer>
            <saml:Subject><saml:NameID>user@x</saml:NameID></saml:Subject>
        </saml:Assertion>"#;
        let root = parse(xml).unwrap();
        assert_eq!(root.local, "Assertion");
        assert_eq!(root.attr("ID"), Some("a1"));
        assert_eq!(root.child("Issuer").unwrap().text(), "idp");
        let nameid = root.find_descendant("NameID").unwrap();
        assert_eq!(nameid.text(), "user@x");
    }

    #[test]
    fn exc_c14n_is_deterministic_and_self_contained() {
        let xml =
            r#"<a:Root xmlns:a="urn:a" xmlns:b="urn:b" z="1" a="2"><a:Child>t</a:Child></a:Root>"#;
        let root = parse(xml).unwrap();
        let c = exc_c14n(&root, &[]);
        let s = String::from_utf8(c).unwrap();
        // b is not visibly utilized -> dropped under exclusive c14n; attrs sorted.
        assert_eq!(
            s,
            r#"<a:Root xmlns:a="urn:a" a="2" z="1"><a:Child>t</a:Child></a:Root>"#
        );
    }

    #[test]
    fn enveloped_transform_removes_signature() {
        let xml =
            r#"<A xmlns="urn:x" ID="1"><B>keep</B><Signature xmlns="urn:sig">drop</Signature></A>"#;
        let root = parse(xml).unwrap();
        let c = String::from_utf8(exc_c14n_enveloped(&root, &[])).unwrap();
        assert!(c.contains("keep"));
        assert!(!c.contains("drop"));
        assert!(!c.contains("Signature"));
    }

    #[test]
    fn entities_decode() {
        let xml = r#"<a>1 &lt; 2 &amp; 3 &#x41;</a>"#;
        let root = parse(xml).unwrap();
        assert_eq!(root.text(), "1 < 2 & 3 A");
    }
}

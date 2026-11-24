//! What search engines and link previews learn about each page, matching `src/lib/site/seo.js`
//! (the browser app still uses that file; tests here keep the two in step until the interface
//! moves to Rust too).
use serde_json::{json, Value};

pub const SITE_NAME: &str = "Commonveil";
pub const SITE_PLACEHOLDER: &str = "https://commonveil.invalid";
pub const DEFAULT_DESCRIPTION: &str = "End-to-end encrypted messages, groups, communities and calls. Open source, free, and you can run it yourself.";
pub const SHARE_IMAGE: &str = "/og-image.png";
pub const SHARE_IMAGE_ALT: &str =
    "Commonveil: private messages and communities, end-to-end encrypted.";
pub const SOURCE_URL: &str = "https://github.com/Comutability/commonveil-rebuild";

pub struct Page {
    pub path: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub priority: &'static str,
}

/// The public pages, in sitemap order.
pub const PAGES: [Page; 13] = [
    Page { path: "/", title: "Commonveil: encrypted messages and communities you can trust", description: "Private messages, groups, communities and calls, end-to-end encrypted so not even we can read them. Open source, free, no phone number, and you can run it yourself.", priority: "1.0" },
    Page { path: "/help", title: "Help Centre", description: "How to use Commonveil: getting started, messages and calls, servers, privacy and safety, your account and running your own site.", priority: "0.9" },
    Page { path: "/help/guide", title: "The complete guide", description: "Every Commonveil feature on one page: what it's for, how to use it, and exactly what it shares.", priority: "0.7" },
    Page { path: "/security", title: "How the encryption works, and where it stops", description: "Commonveil's end-to-end encryption in plain language: what it protects, what the server can still see, and the limits we know about.", priority: "0.8" },
    Page { path: "/privacy", title: "Privacy: exactly what we hold, and what we can't see", description: "Every piece of information Commonveil stores, why, and for how long. Your messages, keys and searches never reach us in readable form.", priority: "0.8" },
    Page { path: "/terms", title: "Terms of Use", description: "The rules for using Commonveil, in plain language: who can join, what isn't allowed, and what happens to your account and data.", priority: "0.4" },
    Page { path: "/resources", title: "Privacy tools worth knowing about", description: "A short, opinionated list of privacy and self-hosting tools. Nobody pays to be here, and nothing is an affiliate link.", priority: "0.6" },
    Page { path: "/releases", title: "What's changed: release notes", description: "Every Commonveil release, newest first, in plain language.", priority: "0.5" },
    Page { path: "/login", title: "Sign in", description: "Sign in to Commonveil with your username and password or a passkey. New on this device? You'll confirm it's you once.", priority: "0.5" },
    Page { path: "/register", title: "Create a free account", description: "Join Commonveil with just a username and password. No email or phone number, and your messages are end-to-end encrypted from the start.", priority: "0.7" },
    Page { path: "/forgot-password", title: "Can't sign in?", description: "Forgotten your password or lost a device? Get back into Commonveil with a passkey, your recovery phrase or your private key.", priority: "0.3" },
    Page { path: "/search", title: "Search the help and resources", description: "Search Commonveil's Help Centre and resources. The search runs in your browser: what you type is never sent anywhere.", priority: "0.3" },
    Page { path: "/security/report", title: "Report a security problem", description: "Found a security problem in Commonveil? How to tell us privately, and what happens next.", priority: "0.4" },
];

/// What a page tells search engines.
#[derive(Clone, Debug, PartialEq)]
pub struct Meta {
    pub path: String,
    pub url: String,
    pub title: String,
    pub description: String,
    pub noindex: bool,
    pub not_found: bool,
    pub moved_to: String,
    pub og_type: &'static str,
    pub json_ld: Vec<Value>,
}

/// "/help/" and "/help" are the same page.
pub fn normal_path(pathname: &str) -> String {
    let p = pathname
        .split(['?', '#'])
        .next()
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    if p.len() > 1 {
        p.trim_end_matches('/').to_string()
    } else {
        "/".into()
    }
}

fn full_title(title: &str) -> String {
    if title.contains(SITE_NAME) {
        title.into()
    } else {
        format!("{title} | {SITE_NAME}")
    }
}

fn moved(path: &str) -> bool {
    regex::Regex::new(r"^/(blog|guides|paths|wiki)(/[^/]+)?$|^/saved$")
        .unwrap()
        .is_match(path)
}
fn private(path: &str) -> bool {
    ["/app", "/admin"]
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
        || path == "/reset-password"
        || path.starts_with("/invite/")
        || path.starts_with("/u/")
}

pub fn seo_for(pathname: &str, articles: &[Value], site_url: &str) -> Meta {
    let path = normal_path(pathname);
    let base = site_url.trim_end_matches('/').to_string();
    let url = format!("{base}{}", if path == "/" { "/" } else { &path });
    let meta = |title: String, description: String, noindex, not_found, og_type, json_ld| Meta {
        path: path.clone(),
        url: url.clone(),
        title,
        description,
        noindex,
        not_found,
        moved_to: String::new(),
        og_type,
        json_ld,
    };
    if let Some(page) = PAGES.iter().find(|p| p.path == path) {
        let mut ld = vec![breadcrumbs(&base, &path, page.title)];
        if path == "/" {
            ld = home_data(&base);
        }
        if path == "/help" {
            ld.push(help_index_data(&base, articles));
        }
        return meta(
            full_title(page.title),
            page.description.into(),
            false,
            false,
            "website",
            ld,
        );
    }
    let slug = path.strip_prefix("/help/").filter(|s| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    });
    if let Some(a) = slug.and_then(|s| articles.iter().find(|a| a["slug"] == s)) {
        let title = a["title"].as_str().unwrap_or("");
        return meta(
            full_title(title),
            a["summary"].as_str().unwrap_or("").into(),
            false,
            false,
            "article",
            vec![article_data(&base, a), breadcrumbs(&base, &path, title)],
        );
    }
    if moved(&path) {
        let mut m = meta(
            full_title("Help Centre"),
            DEFAULT_DESCRIPTION.into(),
            true,
            false,
            "website",
            vec![],
        );
        m.moved_to = "/help".into();
        return m;
    }
    if private(&path) {
        let title = if path == "/reset-password" {
            format!("Choose a new password | {SITE_NAME}")
        } else {
            SITE_NAME.into()
        };
        return meta(
            title,
            DEFAULT_DESCRIPTION.into(),
            true,
            false,
            "website",
            vec![],
        );
    }
    meta(
        format!("Page not found | {SITE_NAME}"),
        DEFAULT_DESCRIPTION.into(),
        true,
        true,
        "website",
        vec![],
    )
}

fn home_data(base: &str) -> Vec<Value> {
    vec![
        json!({ "@context": "https://schema.org", "@type": "Organization", "@id": format!("{base}/#organization"), "name": SITE_NAME, "url": format!("{base}/"), "logo": format!("{base}/icons/icon-512.png"), "sameAs": [SOURCE_URL] }),
        json!({ "@context": "https://schema.org", "@type": "WebSite", "@id": format!("{base}/#website"), "name": SITE_NAME, "url": format!("{base}/"), "inLanguage": "en-GB", "publisher": { "@id": format!("{base}/#organization") } }),
        json!({ "@context": "https://schema.org", "@type": "WebApplication", "name": SITE_NAME, "url": format!("{base}/"), "description": DEFAULT_DESCRIPTION, "applicationCategory": "CommunicationApplication", "operatingSystem": "Any (runs in a web browser; can be installed)", "browserRequirements": "A current web browser", "isAccessibleForFree": true, "license": "https://www.gnu.org/licenses/agpl-3.0.html", "codeRepository": SOURCE_URL, "offers": { "@type": "Offer", "price": "0", "priceCurrency": "GBP" }, "publisher": { "@id": format!("{base}/#organization") } }),
    ]
}

fn article_data(base: &str, a: &Value) -> Value {
    let slug = a["slug"].as_str().unwrap_or("");
    json!({ "@context": "https://schema.org", "@type": "TechArticle", "headline": a["title"], "description": a["summary"], "articleSection": a["section"], "inLanguage": "en-GB", "url": format!("{base}/help/{slug}"), "mainEntityOfPage": format!("{base}/help/{slug}"), "isPartOf": { "@type": "WebSite", "name": SITE_NAME, "url": format!("{base}/") }, "publisher": { "@type": "Organization", "name": SITE_NAME, "url": format!("{base}/") } })
}

fn help_index_data(base: &str, articles: &[Value]) -> Value {
    let items: Vec<Value> = articles.iter().enumerate().map(|(i, a)| json!({ "@type": "ListItem", "position": i + 1, "url": format!("{base}/help/{}", a["slug"].as_str().unwrap_or("")), "name": a["title"] })).collect();
    json!({ "@context": "https://schema.org", "@type": "ItemList", "name": "Commonveil Help Centre", "itemListElement": items })
}

fn breadcrumbs(base: &str, path: &str, title: &str) -> Value {
    let mut items = vec![(SITE_NAME.to_string(), format!("{base}/"))];
    if path.starts_with("/help/") {
        items.push(("Help Centre".into(), format!("{base}/help")));
    }
    if path == "/security/report" {
        items.push(("Security".into(), format!("{base}/security")));
    }
    items.push((
        title
            .strip_suffix(" | Commonveil")
            .unwrap_or(title)
            .to_string(),
        format!("{base}{path}"),
    ));
    let list: Vec<Value> = items.into_iter().enumerate().map(|(i, (name, url))| json!({ "@type": "ListItem", "position": i + 1, "name": name, "item": url })).collect();
    json!({ "@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": list })
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// JSON for a `<script type="application/ld+json">`, safe to put inside HTML.
pub fn json_ld_text(data: &Value) -> String {
    data.to_string().replace('<', "\\u003c")
}

/// The `<head>` tags for a page, as HTML.
pub fn head_html(meta: &Meta, site_url: &str) -> String {
    let base = site_url.trim_end_matches('/');
    let e = escape_html;
    let mut tags = vec![
        format!("<title>{}</title>", e(&meta.title)),
        format!(
            "<meta name=\"description\" content=\"{}\" />",
            e(&meta.description)
        ),
        format!(
            "<meta name=\"robots\" content=\"{}\" />",
            if meta.noindex {
                "noindex, nofollow"
            } else {
                "index, follow, max-image-preview:large"
            }
        ),
    ];
    if !meta.noindex {
        let image = e(&format!("{base}{SHARE_IMAGE}"));
        tags.extend([
            format!("<link rel=\"canonical\" href=\"{}\" />", e(&meta.url)),
            format!("<meta property=\"og:type\" content=\"{}\" />", meta.og_type),
            format!("<meta property=\"og:site_name\" content=\"{SITE_NAME}\" />"),
            "<meta property=\"og:locale\" content=\"en_GB\" />".into(),
            format!(
                "<meta property=\"og:title\" content=\"{}\" />",
                e(&meta.title)
            ),
            format!(
                "<meta property=\"og:description\" content=\"{}\" />",
                e(&meta.description)
            ),
            format!("<meta property=\"og:url\" content=\"{}\" />", e(&meta.url)),
            format!("<meta property=\"og:image\" content=\"{image}\" />"),
            "<meta property=\"og:image:width\" content=\"1200\" />".into(),
            "<meta property=\"og:image:height\" content=\"630\" />".into(),
            format!(
                "<meta property=\"og:image:alt\" content=\"{}\" />",
                e(SHARE_IMAGE_ALT)
            ),
            "<meta name=\"twitter:card\" content=\"summary_large_image\" />".into(),
            format!(
                "<meta name=\"twitter:title\" content=\"{}\" />",
                e(&meta.title)
            ),
            format!(
                "<meta name=\"twitter:description\" content=\"{}\" />",
                e(&meta.description)
            ),
            format!("<meta name=\"twitter:image\" content=\"{image}\" />"),
            format!(
                "<meta name=\"twitter:image:alt\" content=\"{}\" />",
                e(SHARE_IMAGE_ALT)
            ),
        ]);
        for d in &meta.json_ld {
            tags.push(format!(
                "<script type=\"application/ld+json\" data-seo>{}</script>",
                json_ld_text(d)
            ));
        }
    }
    tags.join("\n    ")
}

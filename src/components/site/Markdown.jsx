import React from "react";
import ReactMarkdown from "react-markdown";
import { Link } from "react-router-dom";
import { anchorFor } from "@/lib/site/help.js";

const textOf = (children) => React.Children.toArray(children).map((c) => (typeof c === "string" ? c : textOf(c?.props?.children))).join("");

// Raw HTML in content is never rendered (skipHtml), and react-markdown's default
// URL transform drops javascript: and other unsafe links. Links within this site stay in the
// app (no full page load); headings get anchors so they can be linked to.
const components = {
  a: ({ node: _node, href, children, ...props }) => {
    const external = /^https?:\/\//i.test(href || "");
    if (href && /^\/(?!\/)/.test(href)) return <Link to={href} {...props}>{children}</Link>;
    return (
      <a href={href} {...props} {...(external ? { target: "_blank", rel: "noopener noreferrer nofollow" } : {})}>
        {children}
      </a>
    );
  },
  img: ({ node: _node, src, alt }) => (
    <img src={src} alt={alt || ""} loading="lazy" referrerPolicy="no-referrer" className="rounded-lg border border-border" />
  ),
  h2: ({ node: _node, children }) => <h2 id={anchorFor(textOf(children))} className="scroll-mt-24">{children}</h2>,
  h3: ({ node: _node, children }) => <h3 id={anchorFor(textOf(children))} className="scroll-mt-24">{children}</h3>,
};

export default function Markdown({ children, className = "" }) {
  return (
    <div className={`prose-cv ${className}`}>
      <ReactMarkdown components={components} skipHtml>
        {children || ""}
      </ReactMarkdown>
    </div>
  );
}

import React from "react";
import ReactMarkdown from "react-markdown";

// Raw HTML in content is never rendered (skipHtml), and react-markdown's default
// URL transform drops javascript: and other unsafe links.
const components = {
  a: ({ node: _node, href, children, ...props }) => {
    const external = /^https?:\/\//i.test(href || "");
    return (
      <a href={href} {...props} {...(external ? { target: "_blank", rel: "noopener noreferrer nofollow" } : {})}>
        {children}
      </a>
    );
  },
  img: ({ node: _node, src, alt }) => (
    <img src={src} alt={alt || ""} loading="lazy" referrerPolicy="no-referrer" className="rounded-lg border border-border" />
  ),
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

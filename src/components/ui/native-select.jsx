import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * A plain <select>, styled to match the other inputs.
 *
 * Use this rather than a Radix Select: Radix renders a <style> through innerHTML, which the
 * site's Trusted Types policy blocks, so a page with one crashes on the published site
 * (the editor preview has no policy, so it looks fine there). scripts/check-bundle.mjs
 * fails the build if anything like that creeps back in.
 */
export const NativeSelect = React.forwardRef(function NativeSelect({ className, selectClassName, children, ...props }, ref) {
  return (
    <div className={cn("relative", className)}>
      <select
        ref={ref}
        className={cn(
          "flex h-9 w-full appearance-none rounded-md border border-input bg-background py-1 pl-3 pr-8 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
          selectClassName,
        )}
        {...props}
      >
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 opacity-60" aria-hidden="true" />
    </div>
  );
});

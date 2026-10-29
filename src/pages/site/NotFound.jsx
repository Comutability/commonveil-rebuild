import React from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="container-cv flex min-h-[60vh] flex-col items-start justify-center py-16">
      <p className="eyebrow">404</p>
      <h1 className="mt-3 text-4xl font-semibold">Nothing here</h1>
      <p className="mt-3 max-w-md text-muted-foreground">The page may have moved when Commonveil was rebuilt.</p>
      <Button asChild className="mt-6">
        <Link to="/">Go to the home page</Link>
      </Button>
    </div>
  );
}

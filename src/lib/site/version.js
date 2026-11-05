// This build's version (from package.json, put in by vite.config.js) and its release notes.
import data from "@/content/releases.json";
import { checkReleases, releasedUpTo } from "./releases.js";

/* global __APP_VERSION__ */
export const APP_VERSION = typeof __APP_VERSION__ === "string" ? __APP_VERSION__ : "0.0.0";

export const REPOSITORY = data.repository;

/** Releases up to this build's version, newest first. */
export const RELEASES = releasedUpTo(checkReleases(data), APP_VERSION);

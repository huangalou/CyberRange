"use client";

import type {
  CefExtensionOverrideMap,
  CefHeader,
  CefHeaderOverride,
  CefMappingEntry,
} from "@/lib/api";
import { CefHeaderForm } from "./cef-header-form";
import { CefExtensionsTable } from "./cef-extensions-table";

interface CefMappingEditorProps {
  header: CefHeader;
  mapping: CefMappingEntry[];
  headerOverrides: CefHeaderOverride;
  extensionOverrides: CefExtensionOverrideMap;
  onHeaderChange: (next: CefHeaderOverride) => void;
  onExtensionChange: (next: CefExtensionOverrideMap) => void;
}

/**
 * Wrapper composing the two CEF editor sub-panels. Catalog detail page
 * renders this when `cef_mapping?.length > 0`. State lives in the parent
 * page so PreviewPanel + SendForm can read the same overrides.
 */
export function CefMappingEditor({
  header,
  mapping,
  headerOverrides,
  extensionOverrides,
  onHeaderChange,
  onExtensionChange,
}: CefMappingEditorProps) {
  return (
    <div className="space-y-4">
      <CefHeaderForm
        defaults={header}
        overrides={headerOverrides}
        onChange={onHeaderChange}
      />
      <CefExtensionsTable
        mapping={mapping}
        overrides={extensionOverrides}
        onChange={onExtensionChange}
      />
    </div>
  );
}

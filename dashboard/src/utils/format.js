// Display helper: show snake_case labels with spaces ("registry_key" -> "registry key"). Used only
// when rendering text; the underlying values are left unchanged so filtering, keys and class names
// keep working.
export function humanize(text) {
  return String(text ?? "").replace(/_/g, " ");
}

// DSH Plugin spec compliance shim for the dsh-plugin.org community hub scan.
//
// This bundle is configuration-only: it registers the REA MCP server through
// `cordis.patch.yml` (`@deepseek-ai/dsh-mcp-client`) and exports no Host or
// Client entry points of its own. `apply(ctx)` exists so automated spec scans
// find a well-formed module entry; it intentionally performs no work and owns
// no resources.
export function apply(ctx) {
  void ctx;
  return undefined;
}

export default { apply };

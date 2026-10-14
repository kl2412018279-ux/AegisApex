// dashboard/lib/configParser.ts
// Small hierarchical parser for indentation-style network configs (Cisco IOS /
// IOS-XE / NX-OS / IOS-XR, Arista EOS, Dell OS10, Aruba, Huawei VRP). Lets
// rules ask block-scoped questions ("does EVERY line vty block have an
// access-class?") instead of grepping the whole file for a keyword.

export interface ConfigNode {
  text: string;
  indent: number;
  children: ConfigNode[];
}

const COMMENT_RE = /^\s*(!|#|;|\/\/)/;

function indentOf(line: string): number {
  const match = line.match(/^[ \t]*/);
  return match ? match[0].replace(/\t/g, '    ').length : 0;
}

export function parseIndentedConfig(raw: string): ConfigNode[] {
  const root: ConfigNode = { text: '', indent: -1, children: [] };
  const stack: ConfigNode[] = [root];

  for (const line of (raw || '').split(/\r?\n/)) {
    if (!line.trim() || COMMENT_RE.test(line)) continue;
    const node: ConfigNode = { text: line.trim(), indent: indentOf(line), children: [] };
    while (stack.length > 1 && stack[stack.length - 1].indent >= node.indent) stack.pop();
    stack[stack.length - 1].children.push(node);
    stack.push(node);
  }
  return root.children;
}

/** Top-level blocks whose header line matches `header`. */
export function findBlocks(nodes: ConfigNode[], header: RegExp): ConfigNode[] {
  return nodes.filter((n) => header.test(n.text));
}

/** True if any direct or nested child line of `block` matches `re`. */
export function blockHas(block: ConfigNode, re: RegExp): boolean {
  return block.children.some((c) => re.test(c.text) || blockHas(c, re));
}

/** First child line of `block` (any depth) matching `re`, or undefined. */
export function blockFind(block: ConfigNode, re: RegExp): string | undefined {
  for (const c of block.children) {
    if (re.test(c.text)) return c.text;
    const nested = blockFind(c, re);
    if (nested) return nested;
  }
  return undefined;
}

export function globalLines(nodes: ConfigNode[]): string[] {
  return nodes.map((n) => n.text);
}

/**
 * Interfaces that look unused but are still administratively up: no
 * shutdown, and none of the markers of a port that is actually in use.
 */
export function findUnusedEnabledInterfaces(nodes: ConfigNode[]): string[] {
  const IN_USE = /^(description|ip address|ipv6 address|switchport mode trunk|switchport access vlan|channel-group|no switchport|vrf|encapsulation|service-policy|ip unnumbered|tunnel)/i;
  return findBlocks(nodes, /^interface\s+(?!(vlan|loopback|tunnel|port-channel|bdi|nve|mgmt|management|null))/i)
    .filter((block) => !blockHas(block, /^shutdown$/i) && !blockHas(block, IN_USE))
    .map((block) => block.text.replace(/^interface\s+/i, ''));
}

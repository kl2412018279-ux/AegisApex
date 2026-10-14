import { describe, it, expect } from 'vitest';
import { parseIndentedConfig, findBlocks, blockHas, findUnusedEnabledInterfaces } from '@/lib/configParser';

const CFG = `hostname R1
!
interface Gi0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
!
interface Gi0/2
!
interface Gi0/3
 shutdown
!
interface Vlan10
!
line vty 0 4
 transport input ssh
`;

describe('parseIndentedConfig', () => {
  const tree = parseIndentedConfig(CFG);

  it('nests child lines under their block', () => {
    const gi1 = findBlocks(tree, /^interface Gi0\/1$/)[0];
    expect(gi1.children.map((c) => c.text)).toEqual(['description uplink', 'ip address 10.0.0.1 255.255.255.0']);
  });

  it('skips comment lines', () => {
    expect(tree.some((n) => n.text.startsWith('!'))).toBe(false);
  });

  it('answers block-scoped questions', () => {
    const vty = findBlocks(tree, /^line vty/)[0];
    expect(blockHas(vty, /^transport input ssh$/)).toBe(true);
  });

  it('finds unused enabled physical interfaces only', () => {
    expect(findUnusedEnabledInterfaces(tree)).toEqual(['Gi0/2']);
  });
});

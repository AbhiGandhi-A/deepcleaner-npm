export const KNOWN_MALICIOUS_HASHES: Record<string, { name: string; description: string; reference: string }> = {
  '62660d1f855e96d13b417e4fcfec22a36d2460ce41a7d65f5733f11d1ec9cfa4': {
    name: 'Suspicious npm reverse shell dropper',
    description: 'Known malicious reverse shell script discovered in typosquatted package',
    reference: 'https://blog.sonatype.com/'
  },
  '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': {
    name: 'Trojanized lifecycle hook test payload',
    description: 'Trojanized payload attempting data exfiltration',
    reference: 'https://attack.mitre.org/'
  }
};

export function lookupMaliciousHash(hash: string): { name: string; description: string; reference: string } | undefined {
  return KNOWN_MALICIOUS_HASHES[hash.toLowerCase()];
}

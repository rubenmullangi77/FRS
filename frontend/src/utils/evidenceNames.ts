// User-friendly display names for evidence images while preserving original filenames and paths.
export const EVIDENCE_FRIENDLY_NAMES: Record<string, string> = {
  'carving_evidence.img': 'File Recovery Demo',
  'evidence_demo.img': 'Sample Evidence Image',
  'exfat_evidence.img': 'exFAT Test Evidence',
  'fat32_evidence.img': 'FAT32 Test Evidence',
  'fragmented_evidence.img': 'Fragmented File Demo',
  'ntfs_evidence.img': 'NTFS Test Evidence',
  'sample_disk.img': 'Sample Disk Image',
  'test_bounds.img': 'Boundary Test Image',
  'test_immutability.img': 'Read-Only Safety Test',
  'test_open.img': 'Evidence Access Test',
  'test_ranges.img': 'Sector Range Test',
  'test_sectors.img': 'Sector Reading Test',
  'test_seek.img': 'Disk Seek Test',
};

export function getFriendlyEvidenceName(filename?: string | null): string {
  if (!filename || typeof filename !== 'string') return 'Unknown Evidence';
  const cleanName = filename.replace(/^.*[\\\/]/, '');
  return EVIDENCE_FRIENDLY_NAMES[cleanName] || cleanName.replace(/\.[^/.]+$/, '').replace(/[_-]/g, ' ').toUpperCase();
}

// User-friendly display names for genuine imported evidence images
export function getFriendlyEvidenceName(filename?: string | null): string {
  if (!filename || typeof filename !== 'string') return 'Evidence Image';
  const cleanName = filename.replace(/^.*[\\\/]/, '');
  const title = cleanName.replace(/\.[^/.]+$/, '').replace(/[_-]/g, ' ');
  return title ? (title.charAt(0).toUpperCase() + title.slice(1)) : cleanName;
}


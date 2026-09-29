/**
 * Docspector File Size Formatting Utility
 * Inspect. Verify. Trust.
 */

export function formatFileSize(bytes?: number | null): string {
  if (bytes === undefined || bytes === null || bytes < 0) return '0 B';
  if (bytes === 0) return '0 B';

  const units = ['B', 'KiB', 'MiB', 'GiB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const unitIndex = Math.min(i, units.length - 1);
  const size = bytes / Math.pow(k, unitIndex);

  return `${unitIndex === 0 ? size : size.toFixed(2)} ${units[unitIndex]}`;
}

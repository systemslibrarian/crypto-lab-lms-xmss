/** Parse a manually supplied LMS leaf index without allowing NaN, fractions, or out-of-range state. */
export function parseLeafIndex(raw: string, maxQ: number): number | null {
  if (raw.trim() === '') return null;
  const value = Number(raw);
  return Number.isInteger(value) && value >= 0 && value < maxQ ? value : null;
}

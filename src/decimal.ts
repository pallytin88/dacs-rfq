/**
 * Exact decimal arithmetic on DACS price amounts (CD-1 canonical decimal
 * strings). Prices never go through floating point.
 */

const DECIMAL = /^(0|[1-9][0-9]*)(\.([0-9]*[1-9]))?$/;

export interface Decimal {
  units: bigint;
  scale: number;
}

export function parseDecimal(value: string): Decimal {
  const match = DECIMAL.exec(value);
  if (match === null) throw new Error(`amount is not a canonical decimal: ${value}`);
  const fraction = match[3] ?? "";
  return { units: BigInt(`${match[1]}${fraction}`), scale: fraction.length };
}

function align(a: Decimal, b: Decimal): [bigint, bigint, number] {
  const scale = Math.max(a.scale, b.scale);
  return [a.units * 10n ** BigInt(scale - a.scale), b.units * 10n ** BigInt(scale - b.scale), scale];
}

export function compareDecimal(a: string, b: string): -1 | 0 | 1 {
  const [x, y] = align(parseDecimal(a), parseDecimal(b));
  return x < y ? -1 : x > y ? 1 : 0;
}

export function formatDecimal(value: Decimal): string {
  let units = value.units;
  let scale = value.scale;
  while (scale > 0 && units % 10n === 0n) {
    units /= 10n;
    scale -= 1;
  }
  const digits = units.toString().padStart(scale + 1, "0");
  return scale === 0 ? digits : `${digits.slice(0, -scale)}.${digits.slice(-scale)}`;
}

/** Midpoint rounded half-up to `maxScale` fractional digits. */
export function midpointDecimal(a: string, b: string, maxScale: number): string {
  const [x, y, scale] = align(parseDecimal(a), parseDecimal(b));
  const target = Math.max(scale, maxScale);
  const sum = (x + y) * 10n ** BigInt(target - scale);
  // divide by 2 with half-up rounding at the target scale
  let half = sum / 2n;
  if (sum % 2n !== 0n) half += 1n;
  const rescale = target - maxScale;
  if (rescale > 0) {
    const divisor = 10n ** BigInt(rescale);
    const remainder = half % divisor;
    half = half / divisor + (remainder * 2n >= divisor ? 1n : 0n);
    return formatDecimal({ units: half, scale: maxScale });
  }
  return formatDecimal({ units: half, scale: target });
}

export function maxDecimal(a: string, b: string): string {
  return compareDecimal(a, b) >= 0 ? a : b;
}

export function minDecimal(a: string, b: string): string {
  return compareDecimal(a, b) <= 0 ? a : b;
}

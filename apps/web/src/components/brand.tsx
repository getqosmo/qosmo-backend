/**
 * Brand components.
 *
 * The mark is rendered inline rather than loaded from `/brand/mark.svg` as an
 * image, so it inherits `currentColor` and adapts to light and dark themes and
 * to whatever surface it sits on. One file, two themes, no flash of the wrong
 * colour on load.
 *
 * To drop in different artwork, see `public/brand/README.md`.
 */

export function LogoMark({
  size = 26,
  tone = 'brand',
}: {
  size?: number;
  /** `brand` = filled tile. `mono` = strokes only, inherits currentColor. */
  tone?: 'brand' | 'mono';
}) {
  const stroke = tone === 'brand' ? '#ffffff' : 'currentColor';
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role="img"
      aria-label="MyBot"
      style={{ flexShrink: 0, display: 'block' }}
    >
      {tone === 'brand' ? (
        <rect width="64" height="64" rx="16" className="brand-tile" />
      ) : null}
      {/* Two ascending strokes: an M, and a roofline — MyBot lives in your home. */}
      <path
        d="M16 44V26.5a1.5 1.5 0 0 1 2.56-1.06L32 38.88l13.44-13.44A1.5 1.5 0 0 1 48 26.5V44"
        fill="none"
        stroke={stroke}
        strokeWidth="5.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* The Core. */}
      <circle cx="32" cy="20" r="3.25" fill={stroke} />
    </svg>
  );
}

export function Wordmark({ size = 26 }: { size?: number }) {
  return (
    <div className="brand">
      <LogoMark size={size} />
      <div>
        <div className="brand-name">MyBot</div>
      </div>
    </div>
  );
}

/** The tagline, used on sign-in and nowhere else. Restraint is the point. */
export const TAGLINE = 'Your life. Running itself.';

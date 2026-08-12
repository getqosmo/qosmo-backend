/**
 * Brand components.
 *
 * The mark is a **shelter resting on a line**.
 *
 * The shelter is the product's premise: MyBot lives in your home, on your
 * machine. The line beneath is the boundary it does not cross on its own —
 * MyBot prepares, you approve. Both halves are load-bearing, which is why the
 * baseline is wider than the walls rather than merely underlining them.
 *
 * It replaced an "M" in a rounded tile, which at any real size was
 * indistinguishable from Gmail's mark — an unfortunate thing to resemble when
 * the product's pitch is that it does not read your mail on somebody else's
 * server. Candidates were rendered at 16/24/32/64/128 and on dark before
 * choosing; a mark that only works in a presentation is not a mark.
 *
 * Rendered inline rather than loaded from `/brand/mark.svg` so it inherits
 * `currentColor` and adapts to light and dark without a flash of the wrong
 * colour on load. To drop in different artwork see `public/brand/README.md`.
 */

export function LogoMark({
  size = 26,
  tone = 'brand',
}: {
  size?: number;
  /** `brand` = filled tile. `mono` = strokes only, inherits currentColor. */
  tone?: 'brand' | 'mono';
}) {
  const ink = tone === 'brand' ? '#ffffff' : 'currentColor';
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
      {/* Roof and right wall in one stroke, left wall in another: the join at
          the apex stays crisp at small sizes this way. */}
      <path
        d="M17 30L32 16.5L47 30v10.5"
        fill="none"
        stroke={ink}
        strokeWidth="5.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M17 30v10.5" fill="none" stroke={ink} strokeWidth="5.5" strokeLinecap="round" />
      {/* The line. Wider than the shelter, because it is not an underline. */}
      <rect x="13.5" y="44.5" width="37" height="4.5" rx="2.25" fill={ink} />
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

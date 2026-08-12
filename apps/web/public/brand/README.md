# Brand assets

## The mark

A **shelter resting on a line**.

The shelter is the product's premise: MyBot lives in your home, on your machine.
The line beneath is the boundary it does not cross on its own — MyBot prepares,
you approve. Both halves are load-bearing, which is why the baseline is wider
than the walls rather than merely underlining them.

It replaced an "M" in a rounded tile. At any real size that read as Gmail's
mark, which is an unfortunate thing to resemble when the product's pitch is that
it does not read your mail on somebody else's server. Six candidates were
rendered at 16/24/32/64/128 and on dark before choosing — several died at 16px,
and two carried wrong meanings entirely (a camera, a user avatar). A mark that
only works in a presentation is not a mark.

## Files

| File | What it is |
|---|---|
| `mark.svg` | The mark, filled tile. Source of truth for every raster below |
| `mark-mono.svg` | Strokes only, inherits `currentColor` |
| `wordmark.svg` | Mark plus "MyBot" |
| `icon-180.png` `icon-192.png` `icon-512.png` | Home-screen and PWA icons |
| `og.png` | Link preview, 1200×630 — carries a real screenshot |

The mark is also **inlined** in `src/components/brand.tsx` so it inherits
`currentColor` and adapts to light and dark with no flash of the wrong colour on
load. Change both, or change `mark.svg` and re-derive.

## Regenerating

```bash
npm run screens     # real screenshots — needs the app running
npm run brand       # icons + the OG card (uses shots/today.png)
npm run social      # the social kit
npm run site        # inlines screenshots into www/index.html
```

`npm run brand` will warn and fall back to a plain OG card if the screenshots
are missing, rather than silently producing something worse.

## Dropping in different artwork

Replace `mark.svg`, update the inline copy in `brand.tsx`, then re-run the
commands above. Keep the 64×64 viewBox and the 16-unit corner radius, or the
rasters will need new geometry.

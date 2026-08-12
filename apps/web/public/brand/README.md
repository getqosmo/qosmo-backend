# Brand assets

## Dropping in your own logo

Replace the files below and everything picks them up. Nothing else needs to
change.

| File | Used for | Notes |
|---|---|---|
| `mark.svg` | Sidebar, sign-in, favicon source | Square. Must read at 16px |
| `wordmark.svg` | Sign-in, marketing surfaces | Horizontal lockup |
| `icon-180.png` | Apple touch icon | 180×180 |
| `icon-512.png` | PWA / Android | 512×512 |
| `og.png` | Link previews | 1200×630 |

The React components in `src/components/brand.tsx` render the mark inline as
SVG rather than loading `mark.svg` as an image. That is deliberate: an inline
SVG inherits `currentColor`, so the mark adapts to light and dark themes and to
the surface it sits on without shipping two files. If you replace the mark with
artwork that has fixed colours, swap `<LogoMark>` to render
`<img src="/brand/mark.svg">` instead.

Regenerate the raster assets from the SVGs after any change:

```bash
node scripts/render-brand.mjs
```

## The current mark

Two ascending strokes that read as an **M** and as a **roofline** — MyBot lives
in your home — with a single dot for the Core. Geometric, no gradients at small
sizes, legible in one colour at 16×16.

The palette is one restrained green (`#2f6f5e`) against warm neutrals. There is
deliberately no second accent: in this product, saturated colour is reserved
for things that genuinely need a decision, so the brand itself stays quiet.

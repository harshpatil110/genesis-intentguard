# DESIGN.md — Warm Editorial Minimalism

> Every screen should feel like a beautifully designed product catalog from a Japanese studio that also reads Wallpaper magazine and builds software.

**Role:** Elite UI/UX Designer and Creative Developer.
**Scope:** Applies automatically to all frontend work (React, HTML, Tailwind, CSS, etc.).
**Aesthetic:** A fusion of Japanese spatial restraint, soft brutalism's structural confidence, and the typographic authority of high-end editorial publishing.
**References:** jacobleech.com, simulate.com, minymon.com, high-fashion print layouts translated to the web.

---

## 1. Absolute Prohibitions

Violating any one of these breaks the entire aesthetic.

- No dark mode as a default. The canvas is always warm and light.
- No neon, electric, or saturated colors.
- No purple, magenta, or "AI product" palettes.
- No glowing gradients, aurora effects, or mesh gradients.
- No glassmorphism (no frosted glass, no decorative `backdrop-filter: blur()`).
- No deep drop shadows (`shadow-xl`, `shadow-2xl`, colored glows).
- No pill-shaped primary buttons (`rounded-full`).
- No "SaaS dashboard" tropes (purple sidebars, glowing KPI cards, dark nav rails).
- No decorative gradients on backgrounds. The canvas is a single flat warm tone.
- No heavy border-radius on structural components. Cards are not bubbles.
- No emoji-heavy UI. Icons are crisp SVG line icons or text.

---

## 2. Color System

### Canvas (Background)
The entire app background must be warm light beige or off-white. Non-negotiable. It should feel like high-quality uncoated paper.

| Token | Value | Tailwind |
|---|---|---|
| Primary canvas | `#F7F5F0` | `bg-[#F7F5F0]` / `bg-stone-50` |
| Alternate canvas | `#F2F0EA` | — |

### Accent (single soft light blue)
Calm, like a clear sky at noon. Never electric. **Use in 1–2 places per screen maximum. A whisper, not a shout.**

| Token | Value | Tailwind | Use |
|---|---|---|---|
| Primary accent | `#BFDBFE` | `blue-200` | Subtle fills, upload zones, active states |
| Action accent | `#93C5FD` | `blue-300` | Button borders, highlights |
| Text on accent | `#1E40AF` | `blue-800` | Readable text on light blue fills |
| Focus accent | `#60A5FA` | `blue-400` | Focus rings, active indicators only |

### Text

| Token | Value | Tailwind | Use |
|---|---|---|---|
| Primary | `#1C1917` | `stone-900` | Headings, labels, primary content |
| Secondary | `#78716C` | `stone-500` | Descriptions, placeholders, metadata |
| Disabled / hint | `#A8A29E` | `stone-400` | Inactive, ghost, helper text |

### Borders & Dividers

| Token | Value | Tailwind |
|---|---|---|
| Default border | `#E7E5E4` | `stone-200` |
| Subtle divider | `#F5F5F4` | `stone-100` |
| Emphasis border | `#000000` at 10% opacity | — |
| Dashed (upload/drop) | — | `border-dashed border-stone-300` |

### Surfaces

| Token | Value | Notes |
|---|---|---|
| Card | `#FFFFFF` | Sits atop the beige canvas |
| Elevated | `#FAFAF9` (`stone-50`) | Slightly elevated panels |
| Input | `#FFFFFF` or transparent | Never grey input backgrounds |

---

## 3. Typography

Typography is the most important design tool in this system.

### Font Stack

```css
/* Headings and body */
font-family: 'Inter', 'DM Sans', 'Geist', system-ui, sans-serif;

/* Accent / serif moments (sparingly) */
font-family: 'Playfair Display', 'DM Serif Display', 'Lora', Georgia, serif;

/* Mono (code, IDs, technical labels) */
font-family: 'JetBrains Mono', 'Fira Code', 'Geist Mono', monospace;
```

### Scale & Weight

| Role | Size | Weight | Tracking | Notes |
|---|---|---|---|---|
| Display / Hero | 56–72px | 800–900 | -0.03em | |
| Section heading | 28–36px | 700 | -0.02em | |
| Component title | 18–22px | 600 | -0.01em | |
| UI label | 12–13px | 500 | 0.05–0.1em | UPPERCASE |
| Body | 14–16px | 400 | — | line-height 1.7 |
| Caption / meta | 11–12px | 400 | — | `stone-400` |

### Typographic Rules

1. **Mix weights aggressively.** Contrast between 900-weight headings and 400-weight body creates the editorial drama.
2. **Negative letter-spacing on headings.** Always `tracking-tight` or `-0.02em` on large headings.
3. **Uppercase labels.** Small labels (`text-xs tracking-widest font-medium`) on form fields, section dividers, and category tags.
4. **Serif accents.** Only for pull quotes, key stats, or hero taglines. **One serif moment per screen, maximum.**
5. **Line length.** Cap readable text at `max-width: 65ch`.
6. **No centered body text.** Only hero taglines or very short UI labels may be centered.

---

## 4. Components

### Buttons

| Variant | Styling |
|---|---|
| **Primary** | `bg-stone-900 text-white rounded-sm` (2px) or `rounded` (4px), `px-6 py-2.5`, `text-sm font-medium tracking-wide`, hover `bg-stone-700`. Never `rounded-full`. |
| **Secondary / Outlined** | Transparent, `border border-stone-300`, `text-stone-800`, `rounded-sm`/`rounded`, hover `bg-stone-100 border-stone-400` |
| **Accent** | `bg-blue-100 border border-blue-200 text-blue-800`, `rounded-sm`/`rounded`, hover `bg-blue-200` |
| **Ghost / Destructive** | Transparent, `text-stone-500`, hover `text-stone-900 bg-stone-100` |

### Inputs & Forms

- Background: `bg-white` or transparent
- Border: `border border-stone-300`
- Radius: `rounded-sm` or `rounded` (4–6px max)
- Padding: `px-3 py-2` or `px-4 py-2.5`
- Font: `text-sm`; placeholder `text-stone-400`
- Focus: `outline-none ring-1 ring-blue-300 border-blue-300`
- Label: `text-xs font-medium tracking-wider uppercase text-stone-500`
- **Never:** `rounded-lg`/`rounded-xl` on inputs, grey backgrounds (`bg-gray-100`), or non-light-blue focus rings.

### Cards

- `bg-white border border-stone-200 shadow-sm rounded-lg` (8–12px), padding `p-5` or `p-6`
- Shadow: `shadow-sm` only
- Should feel like sheets of premium paper on the beige canvas.

### Upload / Drop Zones

- Background: `bg-blue-50/50` or transparent
- Border: `border-2 border-dashed border-stone-300`, `rounded-lg`
- Hover: `border-blue-300 bg-blue-50`
- Active: `border-blue-400 bg-blue-100/50`
- Content: `text-stone-400`, centered, minimal copy

### Chat Bubbles (if applicable)

- **User:** `bg-blue-50 border border-blue-100 text-stone-800 rounded-lg`
- **AI:** `bg-white border border-stone-200 text-stone-700 rounded-lg`
- **Timestamps:** `text-xs text-stone-400 font-normal`
- No heavy shadows.

### Navigation (Top Bar / Sidebar)

- Background: `bg-[#F7F5F0]` or `bg-white` (never dark)
- Border: `border-b border-stone-200`
- Logo: `text-stone-900 font-semibold text-lg`
- Links: `text-sm text-stone-500 hover:text-stone-900`
- Active: `text-stone-900 font-medium` (no background pill)

### Loading States

- **Spinner:** simple circular border spinner in `stone-300` / `stone-700` (no glow ring)
- **Pulse:** soft, slow pulsing dot or bar in `blue-200`
- **Skeleton:** `bg-stone-200 animate-pulse rounded`
- **Progress bar:** track `bg-stone-100`, fill `bg-blue-200`, 4px height, no `rounded-full` ends
- No sci-fi animations, particle effects, or multi-colored progress bars.

---

## 5. Layout & Spacing

| Property | Value |
|---|---|
| Max width | `max-w-6xl` (1152px) |
| Horizontal padding | `px-6` mobile, `px-12` desktop |
| Section spacing | `py-16` to `py-24` |
| Grid gaps | `gap-4` to `gap-8` |
| Spacing grid | 8px |

**Whitespace is design.** When in doubt, add more padding. The beige canvas should be generously visible.

**Alignment:** Default to left-aligned. Prefer asymmetric layouts over perfectly symmetrical grids.

---

## 6. 3D & Animation (Gallery / Showcase Views)

### 3D Card Stack

```css
/* Container */
perspective: 1200px;
transform-style: preserve-3d;

/* Cards */
transform: translateX(Npx) translateZ(-Npx) rotateY(Ndeg);
transition: all 0.6s cubic-bezier(0.4, 0, 0.2, 1);
```

- Cards are clean white rectangles (no frosted glass or glows).
- Image occupies the top 75–80% of the card.
- Shadow: `box-shadow: 0 4px 16px rgba(0,0,0,0.08)`
- Hover: subtle `scale(1.02)` or `translateY(-4px)`

### Motion Principles

- Easing: `cubic-bezier(0.4, 0, 0.2, 1)` (smooth, confident, not bouncy)
- Duration: 300–600ms for transitions, 200ms for micro-interactions
- No springy physics, dramatic overshoot, or particle systems.

---

## 7. Admin / Dashboard Panels

- Page background: `#F7F5F0`
- Sidebar: `bg-white border-r border-stone-200`; nav items `text-sm text-stone-600`
- Form section headers: `text-xs font-semibold tracking-widest uppercase text-stone-400 border-b border-stone-200 pb-2 mb-4`
- Fields stacked vertically with 16px gap.

### Data Tables

| Part | Styling |
|---|---|
| Header row | `bg-stone-50 text-xs uppercase tracking-widest text-stone-500` |
| Body rows | `bg-white border-b border-stone-100 text-sm text-stone-700` |
| Row hover | `bg-stone-50/50` |

---

## 8. Responsive Behavior

Design mobile-first, but keep it premium. The warm beige canvas, crisp typography, and generous whitespace must survive every viewport.

| Breakpoint | Behavior |
|---|---|
| Mobile (< 640px) | Single column, reduce heading scale 30–40%, full-width cards, touch targets min 44px, beige canvas maintained |
| Tablet (640–1024px) | 2-column grids, mid-scale typography |
| Desktop (> 1024px) | Full layout, 3–4 column grids, large editorial headings |

---

## 9. Iconography

- Style: outline / line icons (Lucide, Heroicons Outline). Not filled, not rounded-blob.
- Stroke: 1.5px
- Sizes: inline 16px, actions 20px, features 24px
- Color: `text-stone-500` default, `text-stone-900` active

---

## 10. Copy & Content Voice

- **Headings:** confident, editorial, noun-led. ("Transform your image." not "Let's get started!")
- **Descriptions:** sparse. One sentence maximum.
- **CTAs:** direct verbs. ("Upload", "Generate", "Submit". Not "Let's go!" or "Start the magic!")
- **Empty / error states:** minimal, instructional, specific, and calm.

---

## 11. Quick Reference

| Element | Do | Don't |
|---|---|---|
| Background | `bg-[#F7F5F0]` warm beige | White, grey, dark, or gradients |
| Primary text | `text-stone-900` | Soft greys or colored text |
| Accent | Soft `blue-200` / `blue-300` | Purple, teal, green, neon |
| Buttons | `rounded-sm` flat black or outlined | `rounded-full` pill, gradient |
| Cards | White + `border-stone-200` + `shadow-sm` | Glassmorphism, glow, dark cards |
| Inputs | Flat white, `border-stone-300`, small radius | Grey bg, heavy radius, glow focus |
| Headings | 700–900 weight, negative tracking | Medium weight, generic sans |
| Loading | Simple spinner or `blue-200` pulse | Sci-fi bars, neon rings |
| Shadows | `shadow-sm` only | `shadow-xl`, colored shadows |
| Radius | `rounded-sm` to `rounded-lg`, contextual | `rounded-full` on structural UI |
| Motion | Smooth ease, 300–600ms | Spring bounce, particle effects |
| Icons | Outline, 1.5px stroke, `stone-500` | Filled, multicolor, emoji |

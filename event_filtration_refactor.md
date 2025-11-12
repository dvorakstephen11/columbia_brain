Below is an implementation plan that is deliberately exhaustive and specific to the current codebase. It describes **exactly** what to add or change (file by file, API by API, state shape, and rendering details) to support **hundreds or thousands of events** with **10 color‑coded tags**, **events having multiple tags**, **per‑day tag counters (colored circles)**, and a **high‑performance multi‑select tag filter** above the calendar.

---

## 0) Current architecture (what we’re building on)

* **Monthly grid + event chips.** The month view is a fixed 6×7 grid (`CalendarGrid` → `DayCell`) with event chips rendered per day. Events are grouped by day in `CalendarPage` (`eventsByDay` is a `Map<string, Event[]>`) and event details open in `EventPanel`. 
* **Where the day count lives.** `DayCell` currently shows a single gray count pill of “number of events in that day” (top‑right), and then renders every chip for that day. 
* **Event coloring.** Each event currently has a single `category` (e.g., `tech`, `maker`) that maps to `categoryMeta` colors; chips use that background/text color. 
* **Mock data.** Events are created in `frontend/src/data/mockEvents` with one `category` per event, and a `categories` map defines colors/labels.
* **CSS.** Calendar layout and chip styles are in the global stylesheet (e.g., `.calendar-grid`, `.day-cell`, `.event-chip`). We’ll extend these for tag badges and the filter bar.

---

## 1) Data model changes (support multiple tags, scale to thousands)

### 1.1. New Tag registry (10 tags)

Create a new file `frontend/src/data/tags.js` that **replaces** the one‑category notion with a **tag registry**. The object should export:

* `TAGS`: an ordered array of **10 tag IDs** (slugs). Example set (replace with final list):
  `['market','civic','tech','rec','volunteer','maker','library','kids','music','arts']`.
* `tagMetaById`: dictionary keyed by tag ID → `{ id, label, color, textColor, ringColor }`. **Use existing category colors** for the overlapping tags to keep visual continuity. (The current `categories` object has the hexes you’ll reuse as `color`/`textColor` defaults.) 
* `tagIndexById`: `{ [tagId]: 0..9 }` mapping for fast bit‑operations (explained below).

> **Why an ordered registry?** It lets us represent a tag set as a **10‑bit mask** (fits in a number), enabling ultra‑fast filtering and per‑day counting for thousands of events.

### 1.2. Event shape changes

In `frontend/src/data/mockEvents.js` (same file that defines `createEvent` today):

* Keep all existing fields, **add**:

  * `tags: string[]` – for multi‑tag support (include the previous `category` as one of the tags to keep continuity).
  * `tagMask: number` – computed at build time from `tags` using `tagIndexById`.
* **Retain** the existing `category` and `categoryMeta` for backward compatibility of chip coloring for now; we can later switch chips to render an inline tag strip if needed. (This avoids a big styling change up front.)

**Computation:**

* Add a helper `buildTagMask(tags: string[], tagIndexById): number` that sets the bit for each tag present.
  *No code here; implementation note*: `mask |= 1 << tagIndexById[tagId]`.

**Populate tags for existing mock events:**

* For each existing event, set `tags` to `[category, ...extras]`. E.g., a “Makerspace Open Build Night” could have `['maker','arts']`, a “Garden Volunteer Day” could have `['volunteer','rec']`, etc. (The exact seed values don’t matter; structure does.)

### 1.3. Indexes for scale

In `CalendarPage` (or a new `useCalendarIndex` hook), **precompute**:

* `eventById: Map<string, Event>` – for O(1) selection (replaces linear `find`). You currently search with `events.find(...)`. Replace that usage with a map lookup. 
* `eventsByDay: Map<string, Event[]>` – keep as is (you already build this). 
* `dayIndexByKey: Map<string, number>` for the **42 calendar cells** in view. Day key is `date.toDateString()`; maps to a 0..41 **day slot index** (see `generateMonthGrid` usage).
* **Typed counts matrix** for tags: `countsMatrix = new Uint16Array(42 * TAGS.length)` where `index = dayIdx * TAGS.length + tagIdx`. For every event, increment counts for *all* of its tags for the corresponding `dayIdx`. This keeps per‑day per‑tag counts O(1) to read later.

  * For very large datasets, `Uint16` is sufficient until a single day has >65,535 events for one tag (unlikely in our use case).
* `monthTotalsByTag: Uint32Array(TAGS.length)` – total events per tag for the **visible 42 days** (for showing counts on the filter buttons themselves).

> All of the above are computed in `useMemo` keyed by `(visibleMonthKey, events)`. You already compute `calendarDays` with `generateMonthGrid(today)`. Use that array to build `dayIndexByKey` and to zero‑initialize the matrices only when the month changes. 

---

## 2) Filtering model (fast + flexible)

### 2.1. Selection state

In `CalendarPage`, add state:

* `selectedTagMask: number` – bitmask of currently selected tags. `0` means **no filter** (show all).
* `matchMode: 'any' | 'all'` – default `'any'` (an event passes if it has **any** selected tag). Add a tiny toggle to switch to `'all'` semantics (must contain **every** selected tag).

### 2.2. Filtering function (mask‑based)

When producing **filtered events** for rendering:

* If `selectedTagMask === 0`: **do not** filter – return `eventsByDay` lists as is (fast path).
* Else:

  * For **any‑match**: include an event if `(event.tagMask & selectedTagMask) !== 0`.
  * For **all‑match**: include if `(event.tagMask & selectedTagMask) === selectedTagMask`.

> This turns filtering thousands of events into **simple bitwise operations**, minimizing GC pressure and avoiding repeated string set operations.

### 2.3. Per‑day tag‑badge counts under filter

* If `selectedTagMask === 0`: for each day, show **up to N badges** (default N=4) using the **top N tags by count** from `countsMatrix`.
* If `selectedTagMask !== 0`: for each day, compute badges **only for the selected tags**, using `countsMatrix` directly (no per‑render loops over events).
  *Implementation detail*: derive `selectedTagIndices: number[]` from `selectedTagMask` once per change; then `count = countsMatrix[dayIdx * TAGS.length + tagIdx]`.

> This ensures the badge row is **instant** to recompute when selection changes, without touching raw event arrays.

---

## 3) New UI: Tag Filter Bar (above the calendar)

Create `frontend/src/components/TagFilterBar.jsx` and place it **above** `<CalendarGrid />` inside `CalendarPage`.

### 3.1. Props

`<TagFilterBar
  tags={TAGS}
  tagMetaById={tagMetaById}
  monthTotalsByTag={Uint32Array}
  selectedMask={selectedTagMask}
  matchMode={matchMode}
  onToggleTag={(tagId: string) => void}
  onClearAll={() => void}
  onSetMatchMode={(mode: 'any'|'all') => void}
/>`

### 3.2. Rendering requirements

* Render **10 “tag pills”** (buttons) in a responsive row, each:

  * Background color = `tagMetaById[tagId].color`
  * Text color = `tagMetaById[tagId].textColor`
  * A small leading color dot (same color) for scannability.
  * Label = `tagMetaById[tagId].label` and a muted **count** suffix from `monthTotalsByTag[tagIdx]` (only the visible 42 days).
  * ARIA: `role="button"`, `aria-pressed` = boolean. Keyboard accessible, focus ring that meets contrast.
* “Match” control: a compact segmented switch `[ Match ANY | Match ALL ]` with `aria-label="Filter match mode"`.
* “Clear” button on the far right, only shown if `selectedMask !== 0`.
* When a pill is toggled:

  * Flip **its bit** in `selectedMask`.
  * Update URL query string to `?tags=tech,rec&match=any` (for deep linking/shareability). Use `useSearchParams` and update on any state change.
* **Performance**: button handlers must be stable via `useCallback`, and rendering memoized via `React.memo`. Counts and colors come from memoized structures.

### 3.3. Accessibility

* Group the pills in a `role="toolbar"` with a visible heading “Filter by tags”. Provide `aria-controls="calendar"` and add `id="calendar"` to the calendar region (you already label the region; add `id`). 
* Each pill needs an `aria-label` like: *“Tech, 18 events this month, selected”*.

---

## 4) Day tile: show per‑tag colored count circles

Modify `frontend/src/components/DayCell.jsx`:

### 4.1. Props additions

Add two new props:

* `tagBadges: Array<{ tagId: string, count: number }>` – for the **current filter state** (precomputed by the parent; do not compute inside the cell).
* `tagMetaById: Record<string, TagMeta>` – for colors and labels.

> `CalendarGrid` will pass these based on the matrix and selection (see §5).

### 4.2. Visual placement

* Keep the existing **gray** total count pill on the right (unchanged). 
* **Add a row below the header**:
  `div.day-cell__tag-badges` containing **0..N** circular badges. Each badge shows:

  * A **solid, circular background** using the tag color.
  * Inside: a **number** (count).
  * Add a **subtle border** or shadow so dark colors remain legible on light backgrounds.
  * Tooltip/`aria-label`: “*{Tag Label}*: {count} event(s)”.
* If the day has more than N badges to show:

  * Show the first `(N - 1)` and append a final neutral badge `+k` for overflow.
  * Tooltip/`aria-label` for the overflow badge: list the hidden tags and counts (e.g., “+3 more tags: Music 5, Kids 3, Arts 2”).

### 4.3. Badge order

* If **filtered**: order badges by the **TAGS** array order (stable mental model) or by **descending count**; choose one and keep it consistent.
* If **not filtered**: order by **descending count** and break ties by TAGS order.

### 4.4. Accessibility and performance

* Avoid re‑creating arrays per cell; `CalendarGrid` should pass `tagBadges` from memoized helpers.
* Each badge is a `<span>` with `role="img"` and `aria-label`.

### 4.5. CSS additions (no code, but exact classes)

Add to the stylesheet:

* `.day-cell__tag-badges { display:flex; gap:6px; flex-wrap:wrap; }`
* `.tag-badge { display:inline-grid; place-items:center; min-width:22px; height:22px; border-radius:999px; font-weight:600; font-size:12px; line-height:1; box-shadow: var(--shadow-soft); }`
* `.tag-badge--overflow { background: rgba(15,23,42,0.08); color: var(--text-secondary); }`

(Reuse existing CSS tokens and shadows to match the aesthetic.) 

---

## 5) `CalendarGrid` responsibilities

Modify `frontend/src/components/CalendarGrid.jsx`:

### 5.1. New props

* `tagMetaById`
* `tagBadgesByDayKey: Map<string, Array<{tagId, count}>>` – **already filtered** and capped to N per day.
* (Optionally) `maxBadgesPerDay = 4`.

### 5.2. Wiring

When mapping `days` → `DayCell`, obtain:

* `dayKey = day.date.toDateString()`
* `events = eventsByDay.get(dayKey) ?? []` (existing) 
* `tagBadges = tagBadgesByDayKey.get(dayKey) ?? []`

Pass those down. `CalendarGrid` itself **does not** compute counts.

---

## 6) `CalendarPage` orchestration (core changes)

Inside `frontend/src/pages/CalendarPage.jsx`:

1. **Events ingestion**: Convert mocked events to include `tags` and `tagMask`, and build `eventById`. Replace the `selectedEvent` derivation from `find` to `eventById.get(selectedEventId)` for O(1) selection. 
2. **Day indexing**: From `calendarDays`, build `dayIndexByKey` and an array `dayKeys[42]`. You already have `generateMonthGrid` and `weekdayLabels`; reuse them. 
3. **Counts matrix**: Build `countsMatrix` and `monthTotalsByTag`. Iterate **once** over all events that fall within the visible 42 days:

   * Compute `dayKey` from `event.startsAt.toDateString()` (same grouping rule you already use). 
   * If `dayIndexByKey` has this key, increment **each tag** bit present in `event.tagMask` in the `countsMatrix` at `[dayIdx, tagIdx]`, and increment `monthTotalsByTag[tagIdx]`.
4. **Filter state**: Add `selectedTagMask` and `matchMode`. Initialize from URL query (`tags=...`, `match=any|all`).
5. **Filtered events**: In a `useMemo`, build `filteredEventsByDay: Map<string, Event[]>`:

   * Fast path: if `selectedTagMask === 0`, simply return `eventsByDay` (the prebuilt map). 
   * Else, **filter each day’s array** via bit ops once.
6. **Per‑day tag badges**: Build `tagBadgesByDayKey: Map<string, Badge[]>` in a `useMemo` keyed by `(countsMatrix, selectedTagMask)`:

   * If `selectedTagMask === 0`:

     * For each `dayIdx`, read `TAG_COUNT` counts from `countsMatrix` and pick top N with counts > 0.
   * Else:

     * Extract `selectedTagIndices` from the mask and create badges only for those indices (if count > 0). Keep the order consistent (see §4.3).
   * Apply **overflow** rule (N−1 + “+k”).
7. **Totals on filter pills**: The `TagFilterBar` uses `monthTotalsByTag`, which **should reflect the visible month** irrespective of selection (so users see absolute availability while filtering).
8. **Render order**:

   * `<TagFilterBar ... />`
   * `<CalendarGrid ... eventsByDay={filteredEventsByDay} tagBadgesByDayKey={...} tagMetaById={...} />`
   * `<EventPanel ... />`

All expensive structures (`countsMatrix`, `monthTotalsByTag`, `tagBadgesByDayKey`) are **memoized** and only recomputed when the **visible month** or **selection** changes.

---

## 7) Event chip rendering (optional enhancement)

Today, each chip uses one `categoryMeta` for background/text color. You can keep that and treat the first tag (or the legacy `category`) as the **visual “primary”** until you design a multi‑tag chip. (The chip API is already prop‑based and forwards refs; no change required to support thousands of events because we’re not rendering them all—see §9.) 

---

## 8) Performance strategies for large datasets

1. **Bit masks for tag matching** – O(1) per event per filter test; avoids set comparisons.
2. **Typed arrays for counts** – `Uint16Array` for `[42 × 10]` is tiny (~840 bytes) and lets you read counts **without iterating events** on every render.
3. **Only compute for visible month** – the screen shows 42 days; aggregate only for those dates.
4. **Fast event lookup by id** – `eventById` map for panel opening (replace linear `find`). 
5. **Limit per‑day chip rendering** – do **not** render hundreds of chips in a cell. Cap to **3–4 chips** (with a “+N more” link) and open a **day‑level list** in the panel showing all filtered events for that day. Keep existing per‑event panel for details.
6. **Stable callbacks and memoization** – `useCallback` for handlers, `React.memo` for `TagFilterBar` pills and `DayCell` (shallow compare props).
7. **Deferred hydration (optional)** – if you later SSR, you can defer heavy per‑day lists until interaction.

---

## 9) Day‑level overflow handling (so we don’t render 1,000 chips)

* In `DayCell`, after rendering up to K chips (current behavior renders **all** events): instead, render **the first M** filtered events (e.g., M=3), then a small button “**+{remaining} more**”.
* Clicking that button opens the panel with a **scrollable list** of all filtered events for that day (grouped by start time). The current `EventPanel` is a single‑event view; extend it or add a second panel: `DayPanel` that lists events; selecting one slides into the existing `EventPanel`. (This prevents the mount of thousands of `EventChip` instances at once.)

> This change is critical for scalability and can be done in a second iteration. For now, keep per‑event chips but be mindful of capping.

---

## 10) Accessibility details

* **Filter pills** are buttons with `aria-pressed`. Group in a `role="toolbar"` with a labeled heading.
* **Match mode switch**: two radio buttons or a segmented control with `role="radiogroup"`, `aria-checked`.
* **Badge dots in cells**: each has `role="img"` and `aria-label` with tag label and count.
* **Panel focus management**: keep your existing logic (returns focus to the triggering element) – you already manage triggers with `registerTrigger` and refs; don’t break that wiring. 

---

## 11) URL state / persistence

* On tag selection or match mode change, update URL query params.

  * `tags` = comma‑separated slugs in **TAGS order** filtered by the mask.
  * `match` = `any` or `all`.
* On initial load, parse and hydrate `selectedTagMask` + `matchMode` from the URL.

---

## 12) Styling (precise additions, no code)

Add to the main stylesheet (near calendar classes) the following **class names** so devs know where to implement styles:

* **Filter bar**:

  * `.tag-toolbar` (container, aligns with `.calendar-card__header` spacing)
  * `.tag-toolbar__pills` (row; wraps on small screens)
  * `.tag-pill` / `.tag-pill--selected`
  * `.tag-pill__dot` (8px circle)
  * `.tag-toolbar__match` (segmented control)
  * `.tag-toolbar__clear` (secondary action)
* **Day badges**:

  * `.day-cell__tag-badges`
  * `.tag-badge` / `.tag-badge--overflow`

All colors taken from `tagMetaById`. Reuse tokens like `--shadow-soft`, `--text-secondary`, etc., to match the current visual language. 

---

## 13) File‑by‑file changes checklist

1. **`frontend/src/data/tags.js` (new)**

   * Exports: `TAGS`, `tagMetaById`, `tagIndexById`, and a small helper `getTagIndicesFromMask(mask)`.

2. **`frontend/src/data/mockEvents.js` (edit)**

   * Add `tags: string[]` and computed `tagMask: number` to each event.
   * Keep `category`/`categoryMeta` for chip coloring initially.

3. **`frontend/src/pages/CalendarPage.jsx` (edit)**

   * Import `TAGS`, `tagMetaById`, `tagIndexById`.
   * Build `eventById`, `dayIndexByKey`, `countsMatrix`, `monthTotalsByTag`.
   * State: `selectedTagMask`, `matchMode`.
   * Derive `filteredEventsByDay`, `tagBadgesByDayKey`.
   * Render `<TagFilterBar />` above `<CalendarGrid />`. 

4. **`frontend/src/components/TagFilterBar.jsx` (new)**

   * Implements pills, counts, match mode, clear.
   * Emits `onToggleTag`, `onSetMatchMode`, `onClearAll`.

5. **`frontend/src/components/CalendarGrid.jsx` (edit)**

   * New props: `tagMetaById`, `tagBadgesByDayKey`.
   * Pass `tagBadges` and `tagMetaById` to each `DayCell`. 

6. **`frontend/src/components/DayCell.jsx` (edit)**

   * Accept and render `.day-cell__tag-badges` row.
   * Keep existing gray event count and chips for now. 

7. **`frontend/src/components/EventPanel.jsx` (optional future)**

   * Display a row of tag badges for the selected event (use `tags` array for display). Current panel displays the single category badge; extend to multiple fixed‑size badges. 

8. **`frontend/src/styles.css` (edit)**

   * Add the filter bar and tag badge classes listed in §12. 

---

## 14) Complexity and memory notes (for thousands of events)

* **Preprocessing per visible month**: O(E_visible) to fill `countsMatrix` and `eventsByDay`.
* **Filter change**: O(D × T_sel) to recompute day badges, where D=42 and T_sel ≤ 10 (very small).
* **Rendering**: Controlled by capping event chips per day (see §9).
* **Memory**: `countsMatrix` is ~840 bytes; `monthTotalsByTag` is 40 bytes. Most memory is in the event array itself, which you already hold.

---

## 15) Testing plan

* **Unit tests (pure functions)**

  * `buildTagMask()` – correct bit packing.
  * `getTagIndicesFromMask()` – decodes in the proper order.
  * Aggregator: given a small set of events over 3 days, verify `countsMatrix` and `monthTotalsByTag` match expectations.
  * Filter logic for ANY vs ALL.
* **Integration**

  * With 5,000 synthetic events across the visible month:

    * Render time under a threshold (profiling).
    * Toggling pills updates day badges and filtered chips instantly.
    * URL query restores selection on refresh.

---

## 16) Migration strategy (no big bang)

1. **Phase 1**: Add tags and filter bar; keep chips styled by legacy `categoryMeta`. (No visible change to chips; day badges + filter appear.)
2. **Phase 2**: Cap the number of chips per day and add “+N more” → open **DayPanel** listing.
3. **Phase 3**: Consider chip redesign (small tag dots on each chip) and category deprecation if desired.

---

## 17) Edge cases & decisions to lock in

* **Events spanning midnight**: Current grouping uses `startsAt.toDateString()` (single day). Keep that until you implement multi‑day duration rendering. Document as “by start date”. 
* **No selected tags**: The filter bar shows all counts; day badges show top tags for that day (not filtered).
* **All selected but no events**: Show empty badge rows; keep gray total count if there are unfiltered events, or set to 0 if you decide to make the gray count reflect the filtered count (choose one and be consistent).
* **Match mode default**: `'any'` is more forgiving; `'all'` is power‑user.

---

## 18) What stays the same (to minimize risk)

* `generateMonthGrid`, weekday labels, and the 6×7 layout remain unchanged. 
* Focus management and dialog behavior remain intact (you already restore focus to the triggering chip). 
* Overall card layout and theming tokens continue to be used. 

---

### Deliverables summary (ready for tickets)

1. **Data**

   * `tags.js` (registry, meta, index map).
   * Modify mock events: add `tags[]` + `tagMask`.
2. **Indexing in `CalendarPage`**

   * `eventById`, `dayIndexByKey`, `countsMatrix`, `monthTotalsByTag`.
   * State: `selectedTagMask`, `matchMode`.
   * Derivations: `filteredEventsByDay`, `tagBadgesByDayKey`.
3. **Components**

   * `TagFilterBar` (new).
   * `CalendarGrid` (pass tag props).
   * `DayCell` (render tag badges).
4. **Styles**

   * Filter toolbar + tag badges (classes defined above).
5. **Routing**

   * Sync filter state ↔ URL query (`tags`, `match`).
6. **(Optional) DayPanel**

   * A list view for “+N more” per day to avoid rendering hundreds of chips.

This plan keeps the UI familiar, adds a powerful filter, and ensures performance for **thousands** of events by moving heavy work into one‑time aggregations + bitmasks, and by limiting per‑day rendering pressure.

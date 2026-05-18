# UI-V2 Refactoring & Fixes Plan

The application builds successfully and all End-to-End tests pass. However, there are 8 ESLint warnings that need to be resolved to improve code quality, prevent potential re-render bugs, and fix Fast Refresh during development.

Here is what needs to be done:

## 1. Fix missing React Hook Dependencies (`react-hooks/exhaustive-deps`)
These warnings occur when functions used inside a `useEffect` are not included in the dependency array, which can lead to stale closures.

*   **`src/components/screens/Packs.tsx`** (Line 22)
    *   **Fix:** Ensure `loadPacks` is stable by wrapping it in `useCallback` (or move it inside the `useEffect` if it's not used elsewhere), and add it to the dependency array.
*   **`src/components/screens/ProblemsCenter.tsx`** (Line 32)
    *   **Fix:** Wrap `loadProblems` in `useCallback` and add it to the `useEffect` dependency array.
*   **`src/components/screens/Settings.tsx`** (Line 186)
    *   **Fix:** Wrap `refreshSupplementalData` in `useCallback` and add it to the `useEffect` dependency array.

## 2. Fix Fast Refresh Warnings (`react-refresh/only-export-components`)
Fast Refresh in Vite/React requires files to *only* export React components. Exporting regular functions or constants alongside components breaks the hot-reloading mechanism for that file.

*   **`src/components/screens/screenPrimitives.tsx`** (Lines 6, 132, 144, 148, 152)
    *   **Fix:** Extract the exported utility functions and constants into a new dedicated utility file (e.g., `src/components/screens/screenUtils.ts`).
    *   **Fix:** Update all imports across the application that currently import these non-component exports from `screenPrimitives.tsx` to point to the new utility file instead.

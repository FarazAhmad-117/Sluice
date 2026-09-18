/**
 * THE THEME KEY AND THE PRE-PAINT SCRIPT, IN ONE PLACE SO THEY CANNOT DRIFT.
 *
 * This module is imported by TWO consumers that never see each other at
 * runtime: `lib/theme.tsx`, which runs in React, and `vite.config.ts`, which
 * injects the script below into `index.html` at build and dev time. An earlier
 * shape had the script pasted into `index.html` as a literal; the storage key
 * then existed twice, and changing it in one place silently produced a
 * dashboard that flashed the wrong theme on every load with nothing failing.
 *
 * WHY A BLOCKING SCRIPT AT ALL. `index.html` is a static file, so the server
 * always sends the same `data-theme`. A viewer whose system asks for light
 * would see the dark shell paint first and then flip, because React effects
 * run after the first paint. This script is synchronous and sits in `<head>`,
 * so the attribute is already correct when the browser paints for the first
 * time. It is the only inline script in this application, it contains no user
 * data, and it is built here from constants rather than from anything that
 * could carry input.
 *
 * Everything in it is wrapped: `localStorage` throws rather than returning
 * null in a private window with site data blocked, and a throw here happens
 * before the page has painted anything at all.
 */

export const THEME_STORAGE_KEY = "sluice.theme";

/** The document starts here, and the script below corrects it before paint. */
export const THEME_FALLBACK = "dark";

export const THEME_BOOT_SCRIPT = `
(function(){try{
var c=localStorage.getItem(${JSON.stringify(THEME_STORAGE_KEY)});
if(c!=="light"&&c!=="dark"){c=window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}
document.documentElement.setAttribute("data-theme",c);
}catch(e){}})();
`.trim();

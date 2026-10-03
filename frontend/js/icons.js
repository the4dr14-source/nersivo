// Iconos SVG propios (trazo fino, sin dependencias ni imágenes externas).

import { svg } from "./dom.js";

const PATHS = {
  globe: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M3 12h18", "M12 3c2.6 2.7 3.9 5.7 3.9 9s-1.3 6.3-3.9 9c-2.6-2.7-3.9-5.7-3.9-9S9.4 5.7 12 3z"],
  lock: ["M6 11h12v9H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3", "M12 14.5v2.5"],
  network: ["M12 9.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z", "M6 19.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z", "M18 19.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z", "M12 9.5v2.5M12 12l-4.6 3M12 12l4.6 3"],
  mail: ["M4 6h16v12H4z", "M4.5 7l7.5 6 7.5-6"],
  shield: ["M12 3.5l7 2.6v5.4c0 4.4-2.9 7.9-7 9.5-4.1-1.6-7-5.1-7-9.5V6.1z"],
  "shield-check": ["M12 3.5l7 2.6v5.4c0 4.4-2.9 7.9-7 9.5-4.1-1.6-7-5.1-7-9.5V6.1z", "M8.8 12.2l2.2 2.2 4.2-4.4"],
};

/** @param {string} name @param {number} [size] */
export function icon(name, size = 22) {
  const parts = (PATHS[name] || PATHS.globe).map((d) => svg("path", { d }));
  return svg(
    "svg",
    {
      viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor",
      "stroke-width": 1.7, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ui-icon",
    },
    parts
  );
}

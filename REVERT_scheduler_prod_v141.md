# REVERT POINT — scheduler PROD, before wc-v141 promotion
Saved: 2026-06-04 (pre-promotion)

- REVERT TARGET commit: bc9669516f45c7ac0e52802e6ea8c8932ff2955a (bc96695) = wc-v140
  - JS: assets/index-8CjeK27n.js
  - CSS: assets/index-gWo-s4G7.css
  - index.html stamp: wc-v140 ; sw.js CACHE: wc-v140 ; auth-layer BUILD_VERSION: wc-v139
- To roll back: git reset --hard bc96695 ; git push --force-with-lease origin main
- Annotated tag also created: prod-pre-v141  (points at bc96695)

Promotion (wc-v141): JS index-CyDehQip.js, CSS index-V4ZrJKAc.css
Contains: Priority always-visible (resets on service-type change), Priority pink #ff10f0, Google autocomplete regression fix.

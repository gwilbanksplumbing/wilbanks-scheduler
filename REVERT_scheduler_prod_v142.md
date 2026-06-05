# REVERT POINT — scheduler PROD, before wc-v142 promotion
Saved: 2026-06-04 (pre-promotion)

- REVERT TARGET commit: e9767a67dd4af6db5605feb0274a4eef119c9a94 (e9767a6) = wc-v141
  - JS: assets/index-CyDehQip.js ; CSS: assets/index-V4ZrJKAc.css
  - stamps: index.html wc-v141 ; sw.js CACHE wc-v141 ; auth-layer BUILD_VERSION wc-v141
- Roll back: git reset --hard e9767a6 ; git push --force-with-lease origin main  (or: git reset --hard prod-pre-v142)
- Annotated tag: prod-pre-v142 -> e9767a6

Promotion (wc-v142): JS index-z6zur-bu.js (CSS unchanged index-V4ZrJKAc.css)
Change: Customer Info header non-collapsible (clicking title no longer hides customer search field).

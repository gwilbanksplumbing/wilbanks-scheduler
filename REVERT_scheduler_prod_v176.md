# Prod revert point — before wc-v176 promotion (2026-06-06)

Promoted staging wc-v175 -> prod as wc-v176 (frontend-only; tech-visibility build + all wc-v161..v175 refinements).

To roll back to the prior prod (wc-v159):
  cd wilbanks-scheduler-prod
  git reset --hard 6170e53
  git push --force-with-lease origin main

Prior prod bundle: index-CHfDxeXM.js + index-FT2SDJsz.css, wc-v159, auth-layer BUILD_VERSION wc-v159.
Backup copy of prior files: /home/user/workspace/_prod_backup_wc-v159/
Server NOT touched (technician color column already live on Railway since the tech-visibility build).

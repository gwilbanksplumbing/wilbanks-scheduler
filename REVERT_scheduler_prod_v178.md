# Prod revert point — before wc-v178 promotion (2026-06-06)

Promoted staging wc-v177 -> prod as wc-v178 (frontend-only).
Change: Confirm Reschedule dialog buttons (Open/Cancel/Confirm) all uniform outline, blue only on hover.

To roll back to prior prod (wc-v176):
  cd wilbanks-scheduler-prod
  git reset --hard 72a656c
  git push --force-with-lease origin main

Prior prod bundle: index-BRNGs2y5.js + index-DdxL8wd5.css, wc-v176.
Backup of prior files: /home/user/workspace/_prod_backup_wc-v176/
Server NOT touched.

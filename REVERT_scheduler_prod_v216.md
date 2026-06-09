# Prod Revert Point — wc-v216 (pre wc-v242 promotion)

**Captured:** 2026-06-08 night, immediately before promoting wc-v217 through wc-v242 (26 releases in flight) to prod.

## Pre-promotion state
- Prod HEAD: `6d78977` ("Promote to prod wc-v216 (from wc-v212): Settings tab row scroll bleed-through fix")
- Bundle: `index-Cli3xRRc.js` / `index-C6RjI4QT.css`
- `sw.js` CACHE: `wc-v216`
- `auth-layer.js` BUILD_VERSION: `wc-v216`
- Git tag: `pre-promote-wc-v242-2026-06-08-night`
- Full file backup folder: `_prod_backup_wc-v216/` (index.html, auth-layer.js, sw.js, both bundle assets)

## One-command rollback (git)
```
cd /home/user/workspace/prod
git reset --hard pre-promote-wc-v242-2026-06-08-night
git push --force origin main   # WITH CONFIRM
```
GitHub Pages will republish prod at wc-v216 within ~60 seconds.

## File-restore rollback (in case the tag is unreachable)
```
cd /home/user/workspace/prod
cp _prod_backup_wc-v216/index.html .
cp _prod_backup_wc-v216/auth-layer.js .
cp _prod_backup_wc-v216/sw.js .
rm -f assets/index-B3IggoDm.js assets/index-BgE95S83.css
cp _prod_backup_wc-v216/index-Cli3xRRc.js assets/
cp _prod_backup_wc-v216/index-C6RjI4QT.css assets/
git add -A && git commit -m "Revert to wc-v216" && git push origin main   # WITH CONFIRM
```

## Server rollback (if needed)
Server is at `bce4814` (wc-v242). To roll back to v241:
```
cd /home/user/workspace/server
git reset --hard 5a5f8b8   # wc-v241 past-due conflict resolution
git push --force origin main   # WITH CONFIRM
```
Earlier server revert points:
- `9603727` — finance admin-gate + one-click-paid-audit
- `5f5f18d` — _sanitizeCompanyName prevention
- `8d42a9b` — user_preferences table baseline

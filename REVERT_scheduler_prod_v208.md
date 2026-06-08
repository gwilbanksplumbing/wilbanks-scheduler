# PROD REVERT POINT — before wc-v208 promotion

- Date: 2026-06-07 22:12 CDT
- PROD_HEAD (pre-promotion): c083bbd63cd7366afabdfd5f05205e95e32489a8
- Previous version: wc-v190
- Previous JS: index-C6I9Uypu.js
- Previous CSS: index-Cd4MTqjP.css
- Backup files: _prod_backup_wc-v190/

## Rollback
```
cd /home/user/workspace/wilbanks-scheduler-prod
git reset --hard c083bbd63cd7366afabdfd5f05205e95e32489a8
git push --force-with-lease origin HEAD
```

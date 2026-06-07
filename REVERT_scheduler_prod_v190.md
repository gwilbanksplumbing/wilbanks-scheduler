# PROD REVERT POINT — before wc-v190 promotion

- Date: 2026-06-06 23:20 CDT
- PROD_HEAD (pre-promotion): fca9856492bf80f91d126151dd45c38665fe3028
- Previous version: wc-v178
- Previous JS: index-CSCv1wQ9.js
- Previous CSS: index-DdxL8wd5.css
- Backup files: _prod_backup_wc-v178/

## Rollback
```
cd /home/user/workspace/wilbanks-scheduler-prod
git reset --hard fca9856492bf80f91d126151dd45c38665fe3028
git push --force-with-lease origin HEAD
```

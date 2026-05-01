# Wilbanks Company — App Version Manifest
**Last updated: 2026-04-30 (Thursday night session)**

---

## ✅ STABLE VERSIONS (Current — restore these if something breaks)

### Dashboard (Scheduler)
| Property | Value |
|---|---|
| **Stable backup filename** | `index-CQw0lTCk-STABLE-20260430.js` |
| **Live bundle filename** | `index-CQw0lTCk-1777131866.js` |
| **Byte size** | 1,753,571 bytes |
| **MD5** | `acc7d33f10cfbb9443a573bc26ba2d86` |
| **GitHub repo** | `gwilbanksplumbing/wilbanks-scheduler` |
| **GitHub path** | `assets/index-CQw0lTCk-STABLE-20260430.js` |
| **GitHub file SHA** | `ff3711fcf0ec02e8fbbec68e53a41923f4164579` |
| **GitHub commit** | `86290aa78d65d55bd72e947e0e8ea9edad0647d9` |
| **Local path** | `/home/user/workspace/wilbanks-scheduler/assets/index-CQw0lTCk-STABLE-20260430.js` |

**Features in this version:**
- Company name autocomplete in New Appointment form (`_coacSel` sentinel, `_lcAll` data, dropdown closes on select)
- Parts / Labor picker in estimate builder (`{_pick:true}` sentinel, one labor max enforced)
- Line item type tagging (`type: "part"` / `type: "labor"`)
- Residential invoice logic: `_bpIsRes = !companyName` and `_isRes = !companyName` (NOT serviceType)
- QB invoice open in named tab: `window.open(F.qbInvoiceUrl, "wilbanks_qb")`
- Estimate picker does NOT auto-open on estimate load (initial state `[]`, not `[{_pick:true}]`)
- "Convert to Invoice" button in appointment detail panel (`cti` mutation, blue styled button)

---

### Field Tech App
| Property | Value |
|---|---|
| **Stable backup filename** | `index-Dd5Dm7kM-STABLE-20260430.js` |
| **Live bundle filename** | `index-Dd5Dm7kM-FINAL.js` |
| **Byte size** | 360,444 bytes |
| **MD5** | `86850440a4a22500743653d59a1db21b` |
| **GitHub repo** | `gwilbanksplumbing/wilbanks-fieldtech` |
| **GitHub path** | `assets/index-Dd5Dm7kM-STABLE-20260430.js` |
| **GitHub file SHA** | `9afd311192587d7d97aa53b92d7ce7b41787b5eb` |
| **GitHub commit** | `69a737a085dc3eedf6d4c8a34cf4a94de6985dd2` |
| **Local path** | `/home/user/workspace/wilbanks-fieldtech/assets/index-Dd5Dm7kM-STABLE-20260430.js` |

**Features in this version:**
- Parts / Labor picker in estimate builder (same `{_pick:true}` sentinel as dashboard)
- Line item type tagging (`type: "part"` / `type: "labor"`)
- Residential invoice logic uses `!companyName` check
- JWT stored in localStorage for PWA cold launch
- Dark mode default
- Field app bundle is line 8 of the JS file (real minified code on line 8)

---

## How to Restore

### If dashboard breaks — restore STABLE-20260430:
```bash
# 1. Copy stable to live bundle name
cp /home/user/workspace/wilbanks-scheduler/assets/index-CQw0lTCk-STABLE-20260430.js \
   /home/user/workspace/wilbanks-scheduler/assets/index-CQw0lTCk-1777131866.js

# 2. Verify MD5 = acc7d33f10cfbb9443a573bc26ba2d86
md5sum /home/user/workspace/wilbanks-scheduler/assets/index-CQw0lTCk-1777131866.js

# 3. node --check
node --check /home/user/workspace/wilbanks-scheduler/assets/index-CQw0lTCk-1777131866.js

# 4. Push to GitHub (use standard push pattern with api_credentials=["github"])
```

### If field app breaks — restore STABLE-20260430:
```bash
# 1. Copy stable to live bundle name
cp /home/user/workspace/wilbanks-fieldtech/assets/index-Dd5Dm7kM-STABLE-20260430.js \
   /home/user/workspace/wilbanks-fieldtech/assets/index-Dd5Dm7kM-FINAL.js

# 2. Verify MD5 = 86850440a4a22500743653d59a1db21b
md5sum /home/user/workspace/wilbanks-fieldtech/assets/index-Dd5Dm7kM-FINAL.js

# 3. node --check
node --check /home/user/workspace/wilbanks-fieldtech/assets/index-Dd5Dm7kM-FINAL.js

# 4. Push to GitHub (use standard push pattern with api_credentials=["github"])
```

---

## Pre-Session Backups (reference only — do not restore these)

| File | Date | Notes |
|---|---|---|
| `index-CQw0lTCk-1777131866-PRE-COMPANY-AUTOCOMPLETE.js` | 2026-04-30 | Dashboard before company autocomplete was added (1,750,331 bytes) |
| `index-CQw0lTCk-1777131866-PRE-ESTIMATE-TYPES-20260430.js` | 2026-04-30 | Dashboard before estimate type picker (1,748,966 bytes) |
| `index-CQw0lTCk-PRODUCTION-BASELINE-20260428.js` | 2026-04-28 | Baseline before QB login work |
| `index-Dd5Dm7kM-1777258173-PRE-ESTIMATE-TYPES-20260430.js` | 2026-04-30 | Field app before estimate type picker |
| `index-Dd5Dm7kM-1777258173-PRODUCTION-BASELINE-20260429a.js` | 2026-04-29 | Field app baseline from April 29 |
| `index-Dd5Dm7kM-TRUE-BASE.js` | 2026-05-01 | Field app TRUE-BASE (358,501 bytes — before today's estimate work) |

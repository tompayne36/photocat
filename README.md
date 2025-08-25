# PhotoCat

**PhotoCat** is a Python utility to catalog, de-duplicate, and consolidate large photo/video collections into a clean, tagged library.  
It uses **SQLite** to track files, **SHA-256** for duplicate detection, and optionally **ExifTool** to embed tags in file metadata.

---

## Features
- Catalog multiple roots (mark as `--sorted` for folder-derived tags, or `--unsorted` to skip tags).
- Compute hashes with progress + periodic commits (safe to interrupt).
- Detect duplicates and choose canonical files.
- Propose a consolidated layout (`YYYY/YYYY-MM-DD/filename.ext`).
- Export plan as CSV for review in Excel.
- Execute plan:  
  - **Default**: copy files (safe, originals untouched).  
  - **Optional**: hardlink files with `--use-hardlinks` (saves space, but modifying metadata also changes originals).  
- Append folder-derived tags into EXIF/IPTC/XMP keywords with ExifTool.
- Quarantine redundant originals after execution (safe-delete workflow).
- Audit scanned roots with `roots`.

---

## Prerequisites
- Python 3.11+ (tested with 3.11.9)
- [ExifTool](https://exiftool.org/) installed and in PATH (needed for writing tags)
- SQLite3 (for manual inspection, optional; DB is managed automatically)

---

## Typical Workflow

### 1. Scan your roots
```powershell
python photocat.py --db index.db scan --sorted "F:\Photos" --unsorted "F:\PhoneDump"
```

- `--sorted`: folder names become tags (`F:\Photos\Trips\Hawaii2019` → tags `Trips`, `Hawaii2019`).  
- `--unsorted`: files indexed but no tags derived from folders.

Check what roots have been scanned:
```powershell
python photocat.py --db index.db roots
```

---

### 2. Hash the files
```powershell
python photocat.py --db index.db hash
```
- Commits every 500 files (safe to interrupt).
- Add `--limit 1000` to test on smaller batches.

---

### 3. Propose consolidated layout
```powershell
python photocat.py --db index.db propose --library-root "E:\PhotoLibrary"
```

---

### 4. Export plan for review
```powershell
python photocat.py --db index.db export --csv proposed_layout.csv
```
Open in Excel and review columns like `dest_path` and `tags`.

---

### 5. Execute the plan
- **Default: copy (safe, originals untouched)**  
  ```powershell
  python photocat.py --db index.db execute --library-root "E:\PhotoLibrary" --verify --write-tags
  ```
- **Optional: hardlink (saves space, but metadata changes affect originals)**  
  ```powershell
  python photocat.py --db index.db execute --library-root "E:\PhotoLibrary" --use-hardlinks
  ```

Recommended for most users: **copy + write-tags**.

---

### 6. Quarantine redundant originals
```powershell
python photocat.py --db index.db quarantine --quarantine "E:\Quarantine" --execute
```
- Moves duplicates safely to a quarantine folder (mirroring original paths).
- Review and delete when satisfied.

---

## Key Notes
- **Default is copy**: originals remain untouched.  
- Use `--use-hardlinks` only if you fully understand the risks.  
- If you combine `--use-hardlinks` with `--write-tags`, metadata updates will also modify the originals.  
- Hashing is the most time-consuming step; use `--limit` to experiment before full runs.  
- The database (`index.db`) stores everything: file metadata, hashes, plans, logs, roots. Safe to inspect with DB Browser for SQLite.

---

## Example Commands

### Index two roots
```powershell
python photocat.py --db index.db scan --sorted "F:\Photos" --unsorted "F:\PhoneDump"
```

### Hash in batches of 2000
```powershell
python photocat.py --db index.db hash --limit 2000
```

### Propose + Export
```powershell
python photocat.py --db index.db propose --library-root "E:\PhotoLibrary"
python photocat.py --db index.db export --csv proposed_layout.csv
```

### Copy and tag files into new library
```powershell
python photocat.py --db index.db execute --library-root "E:\PhotoLibrary" --verify --write-tags
```

### Quarantine duplicates
```powershell
python photocat.py --db index.db quarantine --quarantine "E:\Quarantine" --execute
```

---

## Inspecting Progress

Count files hashed:
```powershell
sqlite3 index.db "SELECT COUNT(*) FROM media_file WHERE sha256 IS NOT NULL;"
```

Check duplicate groups:
```powershell
sqlite3 index.db "SELECT sha256, COUNT(*) FROM dup_member GROUP BY sha256 HAVING COUNT(*)>1 ORDER BY COUNT(*) DESC LIMIT 10;"
```

---

📌 With this setup you can safely build a **new, clean photo library**, review in CSV before copying, embed tags in your consolidated copies, and eventually quarantine/delete old scattered duplicates.

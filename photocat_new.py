#!/usr/bin/env python3
"""
PhotoCat: Catalog → Hash (file/content) → Propose → Refine (local content) → Export → Execute → Quarantine (SQLite)

Highlights
- Tracks scan roots (audit with `roots`)
- File hash: full-file SHA-256
- Optional content hash: pixel-only via ExifTool stream (ignores metadata)
- Propose/export/execute/quarantine with progress bars
- Default execute action is COPY; use --use-hardlinks to hardlink
- Preserve “special” subfolders under date folders in destination
- NEW: refine-content-local suppresses same-image/different-metadata variants within each date folder

Typical usage (PowerShell/CMD):
  python photocat.py --db index.db scan --sorted "F:\\Photos" --unsorted "F:\\PhoneDump"
  python photocat.py --db index.db hash
  python photocat.py --db index.db propose --library-root "E:\\PhotoLibrary"
  python photocat.py --db index.db refine-content-local --report local_refine.csv --limit-dirs 50
  python photocat.py --db index.db export --csv proposed_layout_after_refine.csv
  python photocat.py --db index.db execute --library-root "E:\\PhotoLibrary" --verify --write-tags
  python photocat.py --db index.db quarantine --quarantine "E:\\Quarantine" --execute
  python photocat.py --db index.db roots
"""

import argparse
import csv
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# ---------- Config ----------
PHOTO_EXTS = {".jpg",".jpeg",".png",".heic",".tif",".tiff",".bmp",".gif",".webp",
              ".dng",".cr2",".nef",".arw",".orf",".rw2"}
VIDEO_EXTS = {".mp4",".mov",".m4v",".avi",".mts",".m2ts",".wmv",".mkv"}
MEDIA_EXTS = PHOTO_EXTS | VIDEO_EXTS

EXT_PRIORITY = [
    ".dng",".cr2",".nef",".arw",".orf",".rw2",  # RAW
    ".heic",".tif",".tiff",
    ".jpg",".jpeg",".png",".webp",".bmp",".gif",
    ".mp4",".mov",".m4v",".avi",".mts",".m2ts",".wmv",".mkv"
]
EXT_RANK = {ext:i for i,ext in enumerate(EXT_PRIORITY)}

# Preserve these folders under the date folder in destination; exclude them from tag derivation
SPECIAL_DIRS_EXACT = {"bad", "originals", ".picasaoriginals", "thumbnails", "_vti_cnf"}
def is_special_dir(name: str) -> bool:
    n = name.lower()
    return n in SPECIAL_DIRS_EXACT or n.startswith("_")

# Non-semantic names to ignore for tags
GENERIC_DIR_NAMES = {"dcim","camera","pictures","photos","images","export",
                     "imports","new","old","sorted","unsorted"}

# ---------- DB (auto-migration) ----------
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;

CREATE TABLE IF NOT EXISTS media_file(
  id          INTEGER PRIMARY KEY,
  root        TEXT NOT NULL,
  path        TEXT NOT NULL UNIQUE,
  size_bytes  INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  ext         TEXT NOT NULL,
  sha256      TEXT,
  capture_dt  TEXT,
  tags_json   TEXT,
  root_mode   TEXT NOT NULL DEFAULT 'sorted',   -- 'sorted' or 'unsorted'
  status      TEXT NOT NULL DEFAULT 'discovered', -- discovered|hashed|planned|error
  image_sha256 TEXT                               -- pixel-only hash (nullable)
);

CREATE TABLE IF NOT EXISTS dup_group(sha256 TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS dup_member(
  sha256 TEXT NOT NULL,
  file_id INTEGER NOT NULL,
  PRIMARY KEY(sha256, file_id),
  FOREIGN KEY(sha256) REFERENCES dup_group(sha256),
  FOREIGN KEY(file_id) REFERENCES media_file(id)
);

-- content-based duplicate grouping (optional)
CREATE TABLE IF NOT EXISTS dup_group_image(image_sha256 TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS dup_member_image(
  image_sha256 TEXT NOT NULL,
  file_id INTEGER NOT NULL,
  PRIMARY KEY(image_sha256, file_id),
  FOREIGN KEY(image_sha256) REFERENCES dup_group_image(image_sha256),
  FOREIGN KEY(file_id) REFERENCES media_file(id)
);

CREATE TABLE IF NOT EXISTS plan(
  sha256          TEXT PRIMARY KEY,      -- group id (file-hash based plan)
  chosen_file_id  INTEGER NOT NULL,
  dest_path       TEXT NOT NULL,
  action          TEXT NOT NULL,         -- 'copy' (proposal note)
  normalized_tags TEXT,
  capture_dt      TEXT,
  executed_at     TEXT,
  FOREIGN KEY (sha256) REFERENCES dup_group(sha256),
  FOREIGN KEY (chosen_file_id) REFERENCES media_file(id)
);

CREATE TABLE IF NOT EXISTS op_log(
  id INTEGER PRIMARY KEY,
  file_id INTEGER,
  op   TEXT NOT NULL,                    -- scan|hash|hash-content|plan|copy|hardlink|tag|verify|skip|quarantine|refine|error
  ts   TEXT DEFAULT (datetime('now')),
  detail TEXT
);

CREATE TABLE IF NOT EXISTS scan_root(
  id         INTEGER PRIMARY KEY,
  root       TEXT NOT NULL UNIQUE,
  mode       TEXT NOT NULL,              -- 'sorted' or 'unsorted'
  scanned_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_media_file_sha ON media_file(sha256);
CREATE INDEX IF NOT EXISTS idx_media_file_status ON media_file(status);
CREATE INDEX IF NOT EXISTS idx_media_file_image_sha ON media_file(image_sha256);
"""

def open_db(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.executescript(SCHEMA_SQL)
    return con

# ---------- Helpers ----------
def is_media(path: Path) -> bool:
    return path.suffix.lower() in MEDIA_EXTS

def sha256sum(path: Path, chunk: int=2**20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for blk in iter(lambda: f.read(chunk), b""):
            h.update(blk)
    return h.hexdigest()

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_exiftool(args: List[str]):
    exe = which("exiftool")
    if not exe:
        return (127,"","exiftool not found")
    p = subprocess.run([exe] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return (p.returncode, p.stdout, p.stderr)

def get_capture_dt(path: Path) -> datetime:
    code, out, _ = run_exiftool(["-j", "-DateTimeOriginal", "-CreateDate", "-MediaCreateDate", str(path)])
    if code == 0 and out.strip():
        try:
            data = json.loads(out)[0]
            for key in ("DateTimeOriginal","CreateDate","MediaCreateDate"):
                if key in data and data[key]:
                    s = data[key].replace(":", "-", 2)
                    return datetime.fromisoformat(s)
        except Exception:
            pass
    return datetime.fromtimestamp(path.stat().st_mtime)

def rel_parts(base: Path, path: Path) -> List[str]:
    """Relative directory parts from base → file parent (for tags/special-dir checks)."""
    try:
        rel = path.parent.relative_to(base)
        return list(rel.parts)
    except Exception:
        return list(path.parent.parts[-4:])

def derive_tags(base: Path, path: Path, mode: str) -> List[str]:
    """Create tags from directory names (for sorted roots), excluding generic/special dirs."""
    if mode == "unsorted":
        return []
    parts = rel_parts(base, path)
    parts = [p for p in parts if p.lower() not in GENERIC_DIR_NAMES and not is_special_dir(p)]
    tokens: List[str] = []
    for p in parts:
        for t in p.replace("_"," ").replace("-"," ").split():
            t = t.strip()
            if t and t.lower() not in GENERIC_DIR_NAMES and not is_special_dir(t):
                tokens.append(t)
    if parts:
        tokens.append(" / ".join(parts))
    seen = set(); out: List[str] = []
    for t in tokens:
        tl = t.lower()
        if tl not in seen:
            seen.add(tl); out.append(t)
    return out

def ext_rank(path: Path) -> int:
    return EXT_RANK.get(path.suffix.lower(), 999)

def choose_canonical(rows: List[Tuple[int, str, int]]) -> int:
    def key(row):
        fid, p, sz = row
        pp = Path(p)
        return (ext_rank(pp), -sz, p)
    return sorted(rows, key=key)[0][0]

def find_special_chain(base: Path, path: Path) -> List[str]:
    """Return the ordered list of special directory components between base and file parent."""
    parts = rel_parts(base, path)
    return [p for p in parts if is_special_dir(p)]

def normalized_dest(library_root: Path, dt: datetime, original_name: str, special_chain: Optional[List[str]]=None) -> Path:
    base = library_root / dt.strftime("%Y") / dt.strftime("%Y-%m-%d")
    if special_chain:
        for comp in special_chain:
            base = base / comp
    return base / original_name

def same_volume(a: Path, b: Path) -> bool:
    return a.drive.lower() == b.drive.lower()

def same_inode(a: Path, b: Path) -> bool:
    try:
        sa, sb = os.stat(a), os.stat(b)
        return (sa.st_ino == sb.st_ino) and (sa.st_dev == sb.st_dev)
    except FileNotFoundError:
        return False

def write_tags_with_exiftool(dest: Path, tags: List[str]) -> Optional[str]:
    if not tags:
        return None
    exe = which("exiftool")
    if not exe:
        return "exiftool not found"
    args = ["-overwrite_original"]
    for t in tags:
        args += [f"-Subject+={t}", f"-Keywords+={t}"]
    args.append(str(dest))
    code, _, err = run_exiftool(args)
    return None if code == 0 else (err or "exiftool error")

def _print_progress(done: int, total: int) -> None:
    pct = (done / total) * 100 if total else 100.0
    bar_len = 30
    filled = int(bar_len * done / total) if total else bar_len
    bar = "#" * filled + "-" * (bar_len - filled)
    print(f"\r[{bar}] {done}/{total} ({pct:5.1f}%)", end="", flush=True)

# ---- Content-hash helpers ----
def _sha256_bytes_iter(byte_iter) -> str:
    h = hashlib.sha256()
    for chunk in byte_iter:
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()

def _exiftool_stream_image_bytes(path: Path):
    """
    Yield raw image bytes via ExifTool:
      - preferred: -b -ImageData
      - fallback:  -b -PreviewImage
      - fallback:  -b -ThumbnailImage
    Return None if exiftool missing or no bytes found.
    """
    exe = which("exiftool")
    if not exe:
        return None
    for tag in ("-ImageData", "-PreviewImage", "-ThumbnailImage"):
        try:
            p = subprocess.Popen([exe, "-b", tag, str(path)],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            got_any = False
            while True:
                chunk = p.stdout.read(1024*1024)
                if not chunk:
                    break
                got_any = True
                yield chunk
            p.stdout.close()
            p.wait()
            if got_any:
                return  # success path (generator fully consumed)
        except Exception:
            continue
    return None

# ---------- Commands ----------
def cmd_scan(con: sqlite3.Connection, sorted_roots: List[str], unsorted_roots: List[str]) -> None:
    cur = con.cursor(); inserted = 0

    def _walk(root_list: List[str], mode: str):
        nonlocal inserted
        for root in root_list:
            rootp = Path(root).expanduser().resolve()
            # record root
            try:
                cur.execute("""
                    INSERT INTO scan_root(root, mode) VALUES(?, ?)
                    ON CONFLICT(root) DO UPDATE SET mode=excluded.mode, scanned_at=datetime('now')
                """, (str(rootp), mode))
            except Exception as e:
                cur.execute("INSERT INTO op_log(file_id,op,detail) VALUES(NULL,'scan',?)",
                            (f"scan_root insert: {rootp}: {e}",))
            for dirpath, _, files in os.walk(rootp):
                d = Path(dirpath)
                for name in files:
                    p = d / name
                    if not is_media(p):
                        continue
                    try:
                        st = p.stat()
                    except FileNotFoundError:
                        continue
                    try:
                        cur.execute("""
                            INSERT OR IGNORE INTO media_file
                              (root, path, size_bytes, mtime_ns, ext, status, root_mode)
                            VALUES(?, ?, ?, ?, ?, 'discovered', ?)
                        """, (str(rootp), str(p), st.st_size, st.st_mtime_ns, p.suffix.lower(), mode))
                        inserted += cur.rowcount
                    except Exception as e:
                        cur.execute("INSERT INTO op_log(file_id,op,detail) VALUES(NULL,'scan',?)", (f"{p}: {e}",))

    _walk(sorted_roots, "sorted")
    _walk(unsorted_roots, "unsorted")
    con.commit()
    print(f"[scan] added {inserted} new records (sorted_roots={len(sorted_roots)}, unsorted_roots={len(unsorted_roots)})")

def cmd_hash(con: sqlite3.Connection, limit: Optional[int]) -> None:
    cur = con.cursor()
    rows = cur.execute("""
        SELECT id, path FROM media_file
        WHERE sha256 IS NULL AND status='discovered'
        ORDER BY id
        LIMIT COALESCE(?, -1)
    """, (limit,)).fetchall()

    total = len(rows)
    print(f"[hash] hashing {total} files...")
    if total == 0:
        return

    updated = 0
    since_commit = 0
    BATCH_COMMIT = 500

    for fid, p in rows:
        path = Path(p)
        try:
            h = sha256sum(path)
            cur.execute("UPDATE media_file SET sha256=?, status='hashed' WHERE id=?", (h, fid))
            cur.execute("INSERT OR IGNORE INTO dup_group(sha256) VALUES(?)", (h,))
            cur.execute("INSERT OR IGNORE INTO dup_member(sha256,file_id) VALUES(?,?)", (h, fid))
            updated += 1
            since_commit += 1
        except Exception as e:
            cur.execute("UPDATE media_file SET status='error' WHERE id=?", (fid,))
            cur.execute("INSERT INTO op_log(file_id,op,detail) VALUES(?, 'hash', ?)", (fid, str(e)))

        if (updated % 50) == 0 or updated == total:
            _print_progress(updated, total)
        if since_commit >= BATCH_COMMIT:
            con.commit()
            since_commit = 0

    con.commit()
    print(f"\n[hash] updated {updated} rows")

def cmd_hash_content(con: sqlite3.Connection, limit: Optional[int]) -> None:
    """Compute pixel-only hashes (image_sha256) without touching existing file hashes."""
    cur = con.cursor()
    rows = cur.execute("""
        SELECT id, path, ext, COALESCE(sha256,'')
        FROM media_file
        WHERE image_sha256 IS NULL
        ORDER BY id
        LIMIT COALESCE(?, -1)
    """, (limit,)).fetchall()

    total = len(rows)
    print(f"[hash-content] computing content hashes for {total} files...")
    if total == 0:
        return

    updated = 0
    since_commit = 0
    BATCH_COMMIT = 300

    for fid, p, ext, full_sha in rows:
        path = Path(p)
        image_sha = None
        try:
            if ext.lower() in PHOTO_EXTS:
                stream = _exiftool_stream_image_bytes(path)
                if stream is not None:
                    image_sha = _sha256_bytes_iter(stream)

            if not image_sha:
                image_sha = full_sha or sha256sum(path)

            cur.execute("UPDATE media_file SET image_sha256=? WHERE id=?", (image_sha, fid))
            cur.execute("INSERT OR IGNORE INTO dup_group_image(image_sha256) VALUES(?)", (image_sha,))
            cur.execute("INSERT OR IGNORE INTO dup_member_image(image_sha256, file_id) VALUES(?,?)", (image_sha, fid))
            updated += 1
            since_commit += 1
        except Exception as e:
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES(?, 'hash-content', ?)", (fid, str(e)))

        if (updated % 50) == 0 or updated == total:
            _print_progress(updated, total)
        if since_commit >= BATCH_COMMIT:
            con.commit()
            since_commit = 0

    con.commit()
    print(f"\n[hash-content] updated {updated} rows")

def cmd_propose(con: sqlite3.Connection, library_root: str) -> None:
    lib = Path(library_root).expanduser().resolve(); lib.mkdir(parents=True, exist_ok=True)
    cur = con.cursor()
    groups = cur.execute("SELECT g.sha256 FROM dup_group g").fetchall()
    total = len(groups)
    print(f"[propose] planning {total} groups...")
    planned = 0

    for idx, (sha,) in enumerate(groups, 1):
        members = cur.execute("""
            SELECT mf.id, mf.path, mf.size_bytes, mf.root, mf.root_mode
            FROM dup_member dm JOIN media_file mf ON mf.id = dm.file_id
            WHERE dm.sha256=?
        """, (sha,)).fetchall()
        if not members:
            continue
        chosen_id = choose_canonical([(fid, p, sz) for fid, p, sz, _, _ in members])
        chosen_row = next(m for m in members if m[0] == chosen_id)
        _, chosen_path, _, chosen_root, chosen_mode = chosen_row
        ppath = Path(chosen_path); base = Path(chosen_root)
        try:
            dt = get_capture_dt(ppath)
        except Exception:
            dt = datetime.fromtimestamp(ppath.stat().st_mtime)

        # Preserve special dir chain beneath date folder
        special_chain = find_special_chain(base, ppath)

        tags = derive_tags(base, ppath, chosen_mode)
        dest = normalized_dest(lib, dt, ppath.name, special_chain=special_chain)
        action = "copy"  # proposal note (execute decides copy vs hardlink)
        tags_json = json.dumps(tags, ensure_ascii=False)
        cur.execute("""
            INSERT INTO plan(sha256, chosen_file_id, dest_path, action, normalized_tags, capture_dt)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(sha256) DO UPDATE SET
              chosen_file_id=excluded.chosen_file_id,
              dest_path=excluded.dest_path,
              action=excluded.action,
              normalized_tags=excluded.normalized_tags,
              capture_dt=excluded.capture_dt
        """, (sha, chosen_id, str(dest), action, tags_json, dt.isoformat()))
        for fid, p, sz, root, mode in members:
            con.execute("UPDATE media_file SET capture_dt=?, tags_json=?, status='planned' WHERE id=?",
                        (dt.isoformat(), tags_json, fid))
        planned += 1

        if (idx % 50) == 0 or idx == total:
            _print_progress(idx, total)

    con.commit()
    print(f"\n[propose] planned {planned} groups")

def _dest_parts(dest_path: str) -> Tuple[str,str,str]:
    dp = Path(dest_path); dest_dir = str(dp.parent); dest_filename = dp.name
    # best-effort relative two-level date dir
    dest_rel_dir = str(Path(dp.parts[-3]) / dp.parts[-2]) if len(dp.parts) >= 3 else ""
    return dest_dir, dest_filename, dest_rel_dir

def cmd_export(con: sqlite3.Connection, csv_path: str, include_all: bool) -> None:
    cur = con.cursor()
    if include_all:
        rows = cur.execute("""
            SELECT p.sha256, CASE WHEN mf.id=p.chosen_file_id THEN 1 ELSE 0 END AS chosen,
                   mf.path, mf.ext, mf.size_bytes, p.dest_path, p.capture_dt, p.normalized_tags,
                   (SELECT COUNT(*) FROM dup_member dm WHERE dm.sha256=p.sha256) AS n
            FROM plan p JOIN dup_member dm ON dm.sha256=p.sha256
                        JOIN media_file mf ON mf.id=dm.file_id
            ORDER BY n DESC, p.sha256, chosen DESC, mf.path
        """).fetchall()
        with open(csv_path,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["sha256","chosen","source_path","ext","size_bytes",
                        "dest_path","dest_dir","dest_rel_dir","dest_filename",
                        "capture_dt","tags","candidate_count"])
            for sha, chosen, source_path, ext, size_bytes, dest_path, capture_dt, tags_json, n in rows:
                dest_dir, dest_filename, dest_rel_dir = _dest_parts(dest_path)
                tags = "|".join(json.loads(tags_json) if tags_json else [])
                w.writerow([sha,chosen,source_path,ext,size_bytes,dest_path,
                            dest_dir,dest_rel_dir,dest_filename,capture_dt,tags,n])
        print(f"[export] wrote {len(rows)} rows (all members) to {csv_path}")
    else:
        rows = cur.execute("""
            SELECT p.sha256, mf.path, mf.ext, mf.size_bytes, p.dest_path, p.capture_dt, p.normalized_tags,
                   (SELECT COUNT(*) FROM dup_member dm WHERE dm.sha256=p.sha256) AS n
            FROM plan p JOIN media_file mf ON mf.id=p.chosen_file_id
            ORDER BY n DESC
        """).fetchall()
        with open(csv_path,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["sha256","chosen_path","ext","size_bytes","dest_path","dest_dir","dest_rel_dir",
                        "dest_filename","capture_dt","tags","candidate_count"])
            for sha, chosen_path, ext, size_bytes, dest_path, capture_dt, tags_json, n in rows:
                dest_dir, dest_filename, dest_rel_dir = _dest_parts(dest_path)
                tags = "|".join(json.loads(tags_json) if tags_json else [])
                w.writerow([sha,chosen_path,ext,size_bytes,dest_path,dest_dir,dest_rel_dir,
                            dest_filename,capture_dt,tags,n])
        print(f"[export] wrote {len(rows)} chosen rows to {csv_path}")

def cmd_execute(con: sqlite3.Connection, library_root: str, use_hardlinks: bool,
                verify: bool, write_tags: bool, limit: Optional[int]) -> None:
    lib = Path(library_root).expanduser().resolve(); lib.mkdir(parents=True, exist_ok=True)
    cur = con.cursor()
    rows = cur.execute("""
        SELECT p.sha256, p.dest_path, p.normalized_tags, p.capture_dt,
               mf.id, mf.path, mf.sha256
        FROM plan p JOIN media_file mf ON mf.id=p.chosen_file_id
        WHERE p.executed_at IS NULL
        ORDER BY p.sha256
        LIMIT COALESCE(?, -1)
    """, (limit,)).fetchall()
    total = len(rows)
    if total == 0:
        print("[execute] nothing to do."); return
    print(f"[execute] processing {total} planned files...")
    if use_hardlinks and write_tags:
        print("[warn] --use-hardlinks + --write-tags will modify originals via hardlink. Proceeding as requested.")

    processed = errors = 0
    for sha, dest_path, tags_json, capture_dt, fid, src_path, src_sha in rows:
        src = Path(src_path); dst = Path(dest_path); dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'skip', 'dest exists')", (fid,))
            cur.execute("UPDATE plan SET executed_at = COALESCE(executed_at, datetime('now')) WHERE sha256=?", (sha,))
            con.commit(); processed += 1; _print_progress(processed, total); continue

        try:
            if use_hardlinks and same_volume(src, dst):
                os.link(src, dst); op = "hardlink"
            else:
                shutil.copy2(str(src), str(dst)); op = "copy"
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, ?, ?)", (fid, op, str(dst)))
        except Exception as e:
            errors += 1
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'error', ?)", (fid, f"{e}"))
            con.commit(); processed += 1; _print_progress(processed, total); continue

        if verify and op == "copy":
            try:
                if src_sha and sha256sum(dst) != src_sha:
                    errors += 1
                    cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'error', 'verify sha mismatch')", (fid,))
                else:
                    cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'verify', 'ok')", (fid,))
            except Exception as e:
                errors += 1
                cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'error', ?)", (fid, f"verify exception: {e}"))

        if write_tags and tags_json:
            try:
                tags = json.loads(tags_json)
            except Exception:
                tags = []
            err = write_tags_with_exiftool(dst, tags)
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'tag', ?)",
                        (fid, 'ok' if not err else f'warn: {err}'))

        cur.execute("UPDATE plan SET executed_at = datetime('now') WHERE sha256=?", (sha,))
        con.commit()
        processed += 1; _print_progress(processed, total)
    print(f"\n[execute] done. processed={processed}, errors={errors}")

# ---------- QUARANTINE ----------
def _sanitize_drive_for_path(drive: str) -> str:
    return drive.replace(":", "").strip("\\/")

def _mirror_quarantine_path(quarantine_root: Path, source_file: Path) -> Path:
    drv = _sanitize_drive_for_path(source_file.drive or "")
    parts = [p for p in source_file.parts if p not in (source_file.drive, "\\", "/")]
    mirrored = quarantine_root / (drv if drv else "_") / Path(*parts)
    mirrored.parent.mkdir(parents=True, exist_ok=True)
    return mirrored

def cmd_quarantine(con: sqlite3.Connection, quarantine_root: str, execute: bool, limit: Optional[int]) -> None:
    qroot = Path(quarantine_root).expanduser().resolve(); qroot.mkdir(parents=True, exist_ok=True)
    cur = con.cursor()
    rows = cur.execute("""
        SELECT m.id, m.path, m.sha256, p.dest_path, p.sha256
        FROM dup_member dm
        JOIN media_file m ON m.id = dm.file_id
        JOIN plan p ON p.sha256 = dm.sha256
        WHERE m.id <> p.chosen_file_id
          AND p.executed_at IS NOT NULL
        LIMIT COALESCE(?, -1)
    """, (limit,)).fetchall()
    total = len(rows)
    if total == 0:
        print("[quarantine] no candidates (nothing executed yet or no duplicates)."); return
    print(f"[quarantine] evaluating {total} duplicates...")
    processed = moved = kept = errors = 0

    def _same_inode(a: Path, b: Path) -> bool:
        try:
            sa, sb = os.stat(a), os.stat(b)
            return (sa.st_ino == sb.st_ino) and (sa.st_dev == sb.st_dev)
        except FileNotFoundError:
            return False

    for file_id, src_path, sha, dest_path, group_sha in rows:
        processed += 1
        src = Path(src_path); dst = Path(dest_path)
        if not src.exists():
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'quarantine', 'source missing')", (file_id,))
            _print_progress(processed, total); continue
        if not dst.exists():
            kept += 1
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'quarantine', 'keep: dest missing')", (file_id,))
            _print_progress(processed, total); continue

        safe = False; reason = ""
        if same_inode(src, dst):
            safe = True; reason = "same inode (hardlink)"
        else:
            try:
                if sha and sha256sum(dst) == sha:
                    safe = True; reason = "sha verified"
                else:
                    reason = "sha mismatch or missing"
            except Exception as e:
                reason = f"sha error: {e}"

        if not safe:
            kept += 1
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'quarantine', ?)", (file_id, f"keep: {reason}"))
            _print_progress(processed, total); continue

        qdest = _mirror_quarantine_path(qroot, src)
        if not execute:
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'quarantine', ?)", (file_id, f"plan -> {qdest} ({reason})"))
            _print_progress(processed, total); continue

        try:
            if qdest.exists():
                os.remove(src)
            else:
                qdest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(qdest))
            moved += 1
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'quarantine', ?)", (file_id, f"moved -> {qdest} ({reason})"))
        except Exception as e:
            errors += 1
            cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'error', ?)", (file_id, f"quarantine move error: {e}"))
        con.commit()
        _print_progress(processed, total)

    print(f"\n[quarantine] done. candidates={total}, moved={moved}, kept={kept}, errors={errors}")

# ---------- REFINE (local content duplicates) ----------
def _score_for_metadata(ext: str, size_bytes: int, tags_json: Optional[str]) -> float:
    """Higher is better: tags count, preferred extension, gentle size bias."""
    tags_count = 0
    if tags_json:
        try:
            tags_count = len(json.loads(tags_json) or [])
        except Exception:
            tags_count = 0
    rank = EXT_RANK.get(ext.lower(), 999)
    ext_score = max(0, 100 - rank)  # RAW/HEIC > JPEG > etc.
    size_score = (size_bytes or 0) ** 0.33
    return (tags_count * 100.0) + (ext_score * 10.0) + size_score

def _image_hash_for_photo(path: Path, fallback_sha256: Optional[str]) -> str:
    stream = _exiftool_stream_image_bytes(path)
    if stream is not None:
        return _sha256_bytes_iter(stream)
    return fallback_sha256 or sha256sum(path)

def cmd_refine_content_local(con: sqlite3.Connection, report_csv: Optional[str], limit_dirs: Optional[int]) -> None:
    """
    Within each proposed date folder (dest_dir), find content duplicates (same image_sha256)
    and suppress all but the 'best' item (more tags, preferred format, larger size).
    Only affects rows already in plan (chosen per file-hash group). Safe to re-run.
    """
    cur = con.cursor()

    # 1) Ensure planned items have image_sha256 (compute only for planned set)
    planned = cur.execute("""
        SELECT p.sha256, p.dest_path, p.normalized_tags, mf.id, mf.path, mf.ext, mf.size_bytes, mf.image_sha256, mf.sha256
        FROM plan p
        JOIN media_file mf ON mf.id = p.chosen_file_id
        WHERE p.executed_at IS NULL
    """).fetchall()

    total = len(planned)
    print(f"[refine] planned, unexecuted items: {total}")
    if total == 0:
        print("[refine] nothing to refine.")
        return

    updated_hashes = 0
    since_commit = 0
    BATCH_COMMIT = 300

    for idx, (sha, dest_path, tags_json, fid, src_path, ext, size_bytes, image_sha, full_sha) in enumerate(planned, 1):
        if not image_sha and ext.lower() in PHOTO_EXTS:
            try:
                image_sha2 = _image_hash_for_photo(Path(src_path), full_sha)
                cur.execute("UPDATE media_file SET image_sha256=? WHERE id=?", (image_sha2, fid))
                updated_hashes += 1
                since_commit += 1
            except Exception as e:
                cur.execute("INSERT INTO op_log(file_id, op, detail) VALUES (?, 'refine', ?)", (fid, f"imagehash error: {e}"))
        if (idx % 100) == 0 or idx == total:
            _print_progress(idx, total)
        if since_commit >= BATCH_COMMIT:
            con.commit(); since_commit = 0
    con.commit()
    print(f"\n[refine] content hashes updated for {updated_hashes} items")

    # 2) Build groups by dest_dir + image_sha256
    rows = cur.execute("""
        SELECT p.sha256, p.dest_path, p.normalized_tags, mf.id, mf.path, mf.ext, mf.size_bytes, COALESCE(mf.image_sha256, mf.sha256) AS ish
        FROM plan p
        JOIN media_file mf ON mf.id = p.chosen_file_id
        WHERE p.executed_at IS NULL
        ORDER BY p.dest_path
    """).fetchall()

    # Optional: limit to first N distinct dest directories (for testing)
    if limit_dirs is not None:
        dirs = []
        for _, dest_path, *_ in rows:
            d = str(Path(dest_path).parent)
            if not dirs or d != dirs[-1]:
                dirs.append(d)
        keep_dirs = set(dirs[:limit_dirs])
        rows = [r for r in rows if str(Path(r[1]).parent) in keep_dirs]
        print(f"[refine] limiting to first {limit_dirs} dest directories ({len(rows)} items).")

    from collections import defaultdict
    by_dir_and_ish = defaultdict(list)
    for sha, dest_path, tags_json, fid, src_path, ext, size_bytes, ish in rows:
        dest_dir = str(Path(dest_path).parent)
        by_dir_and_ish[(dest_dir, ish)].append((sha, dest_path, tags_json, fid, src_path, ext, size_bytes))

    suppressed = []
    for (dest_dir, ish), items in by_dir_and_ish.items():
        if len(items) <= 1:
            continue
        scored = []
        for (sha, dest_path, tags_json, fid, src_path, ext, size_bytes) in items:
            score = _score_for_metadata(ext, size_bytes, tags_json)
            scored.append((score, fid, sha, dest_path, tags_json))
        scored.sort(reverse=True)
        keep = scored[0][1]  # fid
        for score, fid, sha, dest_path, tags_json in scored[1:]:
            cur.execute("UPDATE plan SET executed_at = 'suppressed:content-local' WHERE sha256 = ? AND executed_at IS NULL", (sha,))
            suppressed.append((dest_dir, ish, fid, sha, dest_path, score))
    con.commit()

    print(f"[refine] suppressed {len(suppressed)} locally duplicate items across {len(by_dir_and_ish)} dir+content groups")

    # Optional CSV report
    if report_csv:
        with open(report_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["dest_dir","image_sha256","file_id","sha256_group","dest_path","score","note"])
            for dest_dir, ish, fid, sha, dest_path, score in suppressed:
                w.writerow([dest_dir, ish, fid, sha, dest_path, f"{score:.2f}", "suppressed"])
        print(f"[refine] report written to {report_csv}")

# ---------- ROOTS (audit) ----------
def cmd_roots(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    rows = cur.execute("""
        SELECT r.root, r.mode,
               COALESCE((SELECT COUNT(*) FROM media_file m WHERE m.root=r.root), 0) AS files,
               r.scanned_at
        FROM scan_root r
        ORDER BY r.root
    """).fetchall()
    if not rows:
        print("[roots] no recorded roots yet. Run 'scan' first.")
        return
    print("\nRecorded scan roots:\n")
    print(f"{'Mode':9} {'Files':>8}  {'Scanned At':19}  Root")
    print("-"*80)
    for root, mode, files, scanned_at in rows:
        print(f"{mode:9} {files:8}  {scanned_at:19}  {root}")
    print()

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="PhotoCat (SQLite): catalog/hash/hash-content/propose/refine-content-local/export/execute/quarantine/roots")
    ap.add_argument("--db", required=True, help="Path to SQLite DB (created if missing)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # scan
    ap_scan = sub.add_parser("scan", help="Scan source roots and index files")
    ap_scan.add_argument("--sorted", nargs="+", default=[], help="Roots whose folder names should become tags")
    ap_scan.add_argument("--unsorted", nargs="+", default=[], help="Roots to scan but NOT use for tag derivation")

    # hash (file)
    ap_hash = sub.add_parser("hash", help="Hash un-hashed files (full file) and build duplicate groups")
    ap_hash.add_argument("--limit", type=int, default=None, help="Limit files to hash (batch/testing)")

    # hash-content (pixel-only; optional)
    ap_hashc = sub.add_parser("hash-content", help="Compute content (pixel) hashes; leaves file hashes untouched")
    ap_hashc.add_argument("--limit", type=int, default=None, help="Limit files to hash (batch/testing)")

    # propose
    ap_prop = sub.add_parser("propose", help="Propose canonical, date, tags, destination path (file-hash groups)")
    ap_prop.add_argument("--library-root", required=True, help="Proposed library root (no files written)")

    # refine-content-local
    ap_refine = sub.add_parser("refine-content-local", help="Within each proposed date folder, suppress content-duplicate plans keeping the richest-metadata file")
    ap_refine.add_argument("--report", help="Optional CSV to write suppression decisions", default=None)
    ap_refine.add_argument("--limit-dirs", type=int, default=None, help="Limit to first N destination directories (for testing)")

    # export
    ap_export = sub.add_parser("export", help="Export proposed consolidated layout as CSV")
    ap_export.add_argument("--csv", required=True, help="Output CSV path")
    ap_export.add_argument("--all-members", action="store_true", help="Include every file in each duplicate group")

    # execute
    ap_exec = sub.add_parser("execute", help="Copy (default) or hardlink chosen files into the new library (with progress)")
    ap_exec.add_argument("--library-root", required=True, help="Destination library root")
    ap_exec.add_argument("--use-hardlinks", action="store_true", help="Use hardlinks when possible (same volume). Default is to copy.")
    ap_exec.add_argument("--verify", action="store_true", help="After copy, compute SHA-256 to verify integrity")
    ap_exec.add_argument("--write-tags", action="store_true", help="Append proposed tags to destination files (ExifTool)")
    ap_exec.add_argument("--limit", type=int, default=None, help="Only process this many items (for testing)")

    # quarantine
    ap_quar = sub.add_parser("quarantine", help="Move redundant originals to a quarantine tree (dry-run by default)")
    ap_quar.add_argument("--quarantine", required=True, help="Quarantine root folder")
    ap_quar.add_argument("--execute", action="store_true", help="Actually move files (omit for dry-run)")
    ap_quar.add_argument("--limit", type=int, default=None, help="Limit number of candidates")

    # roots
    sub.add_parser("roots", help="List recorded scan roots with mode and file counts")

    args = ap.parse_args()
    con = open_db(args.db)

    if args.cmd == "scan":
        cmd_scan(con, args.sorted, args.unsorted)
    elif args.cmd == "hash":
        cmd_hash(con, args.limit)
    elif args.cmd == "hash-content":
        cmd_hash_content(con, args.limit)
    elif args.cmd == "propose":
        cmd_propose(con, args.library_root)
    elif args.cmd == "refine-content-local":
        cmd_refine_content_local(con, args.report, args.limit_dirs)
    elif args.cmd == "export":
        cmd_export(con, args.csv, args.all_members)
    elif args.cmd == "execute":
        cmd_execute(con, args.library_root, args.use_hardlinks, args.verify, args.write_tags, args.limit)
    elif args.cmd == "quarantine":
        cmd_quarantine(con, args.quarantine, args.execute, args.limit)
    elif args.cmd == "roots":
        cmd_roots(con)

if __name__ == "__main__":
    main()

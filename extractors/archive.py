import os
import zipfile
import tarfile
import shutil
import tempfile

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

MAX_FILENAME_LEN = 200


def _safe_path(dest: str, member_name: str) -> str | None:
    """Truncate long filenames and sanitize path components."""
    parts = member_name.replace('\\', '/').split('/')
    safe_parts = []
    for part in parts:
        if not part or part in ('.', '..'):
            continue
        name_bytes = part.encode('utf-8', errors='ignore')
        if len(name_bytes) > MAX_FILENAME_LEN:
            base, ext = os.path.splitext(part)
            ext_bytes = ext.encode('utf-8', errors='ignore')
            max_base = MAX_FILENAME_LEN - len(ext_bytes)
            truncated = base.encode('utf-8', errors='ignore')[:max_base].decode('utf-8', errors='ignore')
            part = truncated + ext
        safe_parts.append(part)

    if not safe_parts:
        return None

    full = os.path.normpath(os.path.join(dest, *safe_parts))
    if not full.startswith(os.path.normpath(dest)):
        return None
    return full


class ArchiveExtractor:
    SUPPORTED_EXTENSIONS = {'.rar', '.zip', '.7z', '.tar', '.tar.gz', '.tgz'}

    @staticmethod
    def is_supported(filename: str) -> bool:
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in ArchiveExtractor.SUPPORTED_EXTENSIONS)

    @staticmethod
    def is_encrypted(archive_path: str) -> bool:
        lower = archive_path.lower()
        try:
            if lower.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            return True
                return False
            elif lower.endswith('.rar'):
                if not HAS_RARFILE:
                    return False
                with rarfile.RarFile(archive_path, 'r') as rf:
                    return rf.needs_password()
            elif lower.endswith('.7z'):
                if not HAS_PY7ZR:
                    return False
                with py7zr.SevenZipFile(archive_path, 'r') as sz:
                    return sz.needs_password()
        except Exception:
            return False
        return False

    @staticmethod
    def file_count(archive_path: str) -> int:
        """Count extractable files without extracting."""
        lower = archive_path.lower()
        try:
            if lower.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    return sum(1 for m in zf.infolist() if not m.is_dir())
            elif lower.endswith('.rar'):
                if not HAS_RARFILE:
                    return 0
                with rarfile.RarFile(archive_path, 'r') as rf:
                    return sum(1 for m in rf.infolist() if not m.is_dir())
            elif lower.endswith('.7z'):
                if not HAS_PY7ZR:
                    return 0
                with py7zr.SevenZipFile(archive_path, 'r') as sz:
                    return len(sz.getnames())
            elif lower.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(archive_path, 'r:*') as tf:
                    return sum(1 for m in tf.getmembers() if m.isfile())
        except Exception:
            return 0
        return 0

    @staticmethod
    def extract(archive_path: str, dest_dir: str = None, password: str = None,
                progress_cb=None) -> str:
        """Extract archive. progress_cb(extracted, total) called per file."""
        if dest_dir is None:
            dest_dir = tempfile.mkdtemp(prefix='stex_')

        os.makedirs(dest_dir, exist_ok=True)
        lower = archive_path.lower()

        if lower.endswith('.zip'):
            ArchiveExtractor._extract_zip(archive_path, dest_dir, password, progress_cb)
        elif lower.endswith('.rar'):
            ArchiveExtractor._extract_rar(archive_path, dest_dir, password, progress_cb)
        elif lower.endswith('.7z'):
            ArchiveExtractor._extract_7z(archive_path, dest_dir, password, progress_cb)
        elif lower.endswith(('.tar', '.tar.gz', '.tgz')):
            ArchiveExtractor._extract_tar(archive_path, dest_dir, progress_cb)
        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")

        return dest_dir

    @staticmethod
    def _extract_zip(path, dest, password=None, progress_cb=None):
        pwd = password.encode('utf-8') if password else None
        with zipfile.ZipFile(path, 'r') as zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            total = len(members)
            for i, member in enumerate(members, 1):
                out_path = _safe_path(dest, member.filename)
                if not out_path:
                    if progress_cb:
                        progress_cb(i, total)
                    continue
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with zf.open(member, pwd=pwd) as src, open(out_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    pass
                if progress_cb:
                    progress_cb(i, total)

    @staticmethod
    def _extract_rar(path, dest, password=None, progress_cb=None):
        if not HAS_RARFILE:
            raise ImportError("rarfile package required for RAR archives")
        with rarfile.RarFile(path, 'r') as rf:
            if password:
                rf.setpassword(password)
            members = [m for m in rf.infolist() if not m.is_dir()]
            total = len(members)
            for i, member in enumerate(members, 1):
                out_path = _safe_path(dest, member.filename)
                if not out_path:
                    if progress_cb:
                        progress_cb(i, total)
                    continue
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with rf.open(member) as src, open(out_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                except (OSError, rarfile.BadRarFile, rarfile.RarCRCError):
                    pass
                if progress_cb:
                    progress_cb(i, total)

    @staticmethod
    def _extract_7z(path, dest, password=None, progress_cb=None):
        if not HAS_PY7ZR:
            raise ImportError("py7zr package required for 7z archives")
        kwargs = {'mode': 'r'}
        if password:
            kwargs['password'] = password
        with py7zr.SevenZipFile(path, **kwargs) as sz:
            entries = sz.readall()
            if entries is None:
                return
            total = len(entries)
            for i, (member_name, bio) in enumerate(entries.items(), 1):
                out_path = _safe_path(dest, member_name)
                if not out_path:
                    if progress_cb:
                        progress_cb(i, total)
                    continue
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as dst:
                        shutil.copyfileobj(bio, dst)
                except OSError:
                    pass
                if progress_cb:
                    progress_cb(i, total)

    @staticmethod
    def _extract_tar(path, dest, progress_cb=None):
        with tarfile.open(path, 'r:*') as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            total = len(members)
            for i, member in enumerate(members, 1):
                out_path = _safe_path(dest, member.name)
                if not out_path:
                    if progress_cb:
                        progress_cb(i, total)
                    continue
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with tf.extractfile(member) as src, open(out_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                except (OSError, KeyError):
                    pass
                if progress_cb:
                    progress_cb(i, total)

    @staticmethod
    def cleanup(path: str):
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)

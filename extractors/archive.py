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


class ArchiveExtractor:
    SUPPORTED_EXTENSIONS = {'.rar', '.zip', '.7z', '.tar', '.tar.gz', '.tgz'}

    @staticmethod
    def is_supported(filename: str) -> bool:
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in ArchiveExtractor.SUPPORTED_EXTENSIONS)

    @staticmethod
    def extract(archive_path: str, dest_dir: str = None) -> str:
        if dest_dir is None:
            dest_dir = tempfile.mkdtemp(prefix='stex_')

        os.makedirs(dest_dir, exist_ok=True)
        lower = archive_path.lower()

        if lower.endswith('.zip'):
            ArchiveExtractor._extract_zip(archive_path, dest_dir)
        elif lower.endswith('.rar'):
            ArchiveExtractor._extract_rar(archive_path, dest_dir)
        elif lower.endswith('.7z'):
            ArchiveExtractor._extract_7z(archive_path, dest_dir)
        elif lower.endswith(('.tar', '.tar.gz', '.tgz')):
            ArchiveExtractor._extract_tar(archive_path, dest_dir)
        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")

        return dest_dir

    @staticmethod
    def _extract_zip(path, dest):
        with zipfile.ZipFile(path, 'r') as zf:
            zf.extractall(dest)

    @staticmethod
    def _extract_rar(path, dest):
        if not HAS_RARFILE:
            raise ImportError(
                "rarfile package is required for RAR archives. "
                "Install with: pip install rarfile\n"
                "Also requires UnRAR tool: https://www.rarlab.com/rar_add.htm"
            )
        with rarfile.RarFile(path, 'r') as rf:
            rf.extractall(dest)

    @staticmethod
    def _extract_7z(path, dest):
        if not HAS_PY7ZR:
            raise ImportError(
                "py7zr package is required for 7z archives. "
                "Install with: pip install py7zr"
            )
        with py7zr.SevenZipFile(path, 'r') as sz:
            sz.extractall(dest)

    @staticmethod
    def _extract_tar(path, dest):
        with tarfile.open(path, 'r:*') as tf:
            tf.extractall(dest)

    @staticmethod
    def cleanup(path: str):
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)

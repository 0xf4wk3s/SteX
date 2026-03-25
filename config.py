import os


class Config:
    SECRET_KEY = os.environ.get('STEX_SECRET_KEY', os.urandom(32).hex())
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'rar', 'zip', '7z', 'tar', 'gz', 'tgz'}

    @staticmethod
    def init():
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

"""
Jinja2 custom template filters for SecureVault.
Registered in main.py at startup.
"""


def filesizeformat(value: int) -> str:
    """Convert a byte count into a human-readable size."""
    if value < 1024:
        return f"{value} B"
    elif value < 1024 ** 2:
        return f"{value / 1024:.1f} KB"
    elif value < 1024 ** 3:
        return f"{value / (1024**2):.1f} MB"
    else:
        return f"{value / (1024**3):.1f} GB"


def file_icon(filename: str) -> str:
    """Return a file-type emoji based on extension."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    icons = {
        "pdf": "📄", "doc": "📝", "docx": "📝",
        "xls": "📊", "xlsx": "📊", "csv": "📊",
        "ppt": "📑", "pptx": "📑",
        "jpg": "🖼️", "jpeg": "🖼️", "png": "🖼️", "gif": "🖼️", "webp": "🖼️", "svg": "🖼️",
        "mp4": "🎬", "avi": "🎬", "mov": "🎬", "mkv": "🎬",
        "mp3": "🎵", "wav": "🎵", "flac": "🎵",
        "zip": "🗜️", "rar": "🗜️", "7z": "🗜️", "tar": "🗜️",
        "py": "🐍", "js": "📜", "ts": "📜", "json": "📋",
        "txt": "📄", "md": "📄",
        "html": "🌐", "css": "🎨",
    }
    return icons.get(ext, "📁")

import re
from pathlib import Path
from typing import List, Set

STOP_WORDS: Set[str] = {
    # Articles & conjunctions
    "the", "a", "an", "and", "or", "but", "nor", "so", "yet",

    # Prepositions
    "of", "in", "on", "at", "to", "for", "with", "by", "from", "into", "onto",

    # Pronouns
    "my", "your", "our", "its", "their", "this", "that", "these", "those",

    # Version indicators
    "v1", "v2", "v3", "v4", "v5", "ver", "version", "rev", "revision",
    "r1", "r2", "r3",

    # Draft / status
    "draft", "final", "copy", "original", "master", "template", "sample",
    "example", "demo", "test", "temp", "tmp", "wip", "backup", "bak",

    # Temporal
    "new", "old", "latest", "updated", "current", "previous", "last",
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",

    # Numbering
    "1", "2", "3", "4", "5", "one", "two", "three",

    # Common filler words
    "misc", "other", "general", "common", "default", "untitled", "unnamed",
    "file", "folder", "document", "doc", "data", "info", "report",
}

EXTENSION_CATEGORIES = {
    "document": {
        ".pdf", ".docx", ".doc", ".txt", ".md", ".rtf", ".odt", ".tex", ".epub", ".pages"
    },
    "spreadsheet": {
        ".xlsx", ".xls", ".csv", ".tsv", ".ods", ".numbers"
    },
    "presentation": {
        ".pptx", ".ppt", ".odp", ".key"
    },
    "image": {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".tiff", ".ico", ".heic", ".raw"
    },
    "video": {
        ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".m4v", ".mpeg"
    },
    "audio": {
        ".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a", ".wma", ".opus"
    },
    "archive": {
        ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz", ".tar.gz"
    },
    "code": {
        ".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".yaml", ".yml",
        ".java", ".c", ".cpp", ".h", ".cs", ".go", ".rb", ".php", ".swift",
        ".kt", ".rs", ".sh", ".bat", ".sql"
    },
    "font": {
        ".ttf", ".otf", ".woff", ".woff2", ".eot"
    },
    "database": {
        ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"
    },
    "executable": {
        ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".appimage"
    },
    "config": {
        ".env", ".ini", ".cfg", ".conf", ".toml", ".properties"
    },
}

def extract_entities_stage_1(virtual_path: str) -> List[str]:
    """
    Extracts deterministic semantic tags from a file path.
    """
    tags: Set[str] = set()
    path_obj = Path(virtual_path)
    
    if path_obj.name == path_obj.parent.name or not path_obj.suffix:
        filename = path_obj.name
    else:
        filename = path_obj.stem
        suffix = path_obj.suffix.lower()

        for category, ext_set in EXTENSION_CATEGORIES.items():
            if suffix in ext_set:
                tags.add(category)
                break

    date_pattern = r'\b20\d{2}(?:-\d{2}-\d{2})?\b'
    matched_dates = re.findall(date_pattern, filename)
    tags.update(matched_dates)

    words = re.sub(r'[_-]', ' ', filename).split()
    for word in words:
        if word not in STOP_WORDS and len(word) >= 3:
            tags.add(word.lower())

    return sorted(list(tags))
import os
import uuid
import logging

logger = logging.getLogger("storage")

# Root directory to store attachments safely on disk
ATTACHMENT_STORAGE_DIR = os.getenv("ATTACHMENT_STORAGE_DIR", "data/attachments")

def save_attachment_file(file_id: uuid.UUID, filename: str, content: bytes) -> str:
    """Saves attachment binary payload to a secure storage path on disk.
    Returns the resolved physical path.
    """
    os.makedirs(ATTACHMENT_STORAGE_DIR, exist_ok=True)
    
    # Sanitize file name to prevent path traversal attacks
    safe_filename = os.path.basename(filename)
    if not safe_filename:
        safe_filename = "unnamed_file"
        
    # Store using UUID partition prefix to ensure uniqueness and prevent naming clashes
    storage_filename = f"{str(file_id)}_{safe_filename}"
    storage_path = os.path.abspath(os.path.join(ATTACHMENT_STORAGE_DIR, storage_filename))
    
    # Double check path constraint
    if not storage_path.startswith(os.path.abspath(ATTACHMENT_STORAGE_DIR)):
        raise ValueError("Attempted path traversal attack detected in attachment filename.")
        
    try:
        with open(storage_path, "wb") as f:
            f.write(content)
        return storage_path
    except Exception as e:
        logger.error(f"Failed to write attachment {filename} to disk: {str(e)}")
        raise OSError(f"Secure attachment write error: {str(e)}")

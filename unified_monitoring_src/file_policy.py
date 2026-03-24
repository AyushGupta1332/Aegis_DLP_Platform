"""
File Policy Checker for Unified File Monitoring System
=======================================================
Handles file type restrictions to prevent malware/executable transfers.
Supports blacklist and whitelist modes with archive scanning.
"""

import logging
import zipfile
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from enum import Enum

# Optional: python-magic for file header (magic byte) validation
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# Configure logger
logger = logging.getLogger('file_policy')

# MIME type to expected extensions mapping (for mismatch detection)
MIME_EXTENSION_MAP = {
    'application/x-dosexec': {'.exe', '.dll', '.com', '.scr', '.pif'},
    'application/x-executable': {'.exe', '.dll', '.com'},
    'application/x-msdos-program': {'.exe', '.com', '.bat'},
    'application/x-msdownload': {'.exe', '.dll', '.msi'},
    'application/x-bat': {'.bat', '.cmd'},
    'application/x-msi': {'.msi'},
    'application/x-sharedlib': {'.dll', '.so'},
    'application/java-archive': {'.jar'},
    'application/javascript': {'.js'},
    'text/x-python': {'.py'},
    'application/x-shellscript': {'.sh', '.bash'},
    'application/vnd.microsoft.portable-executable': {'.exe', '.dll', '.sys'},
}


class PolicyMode(Enum):
    """File policy modes."""
    BLACKLIST = "blacklist"  # Block specific file types
    WHITELIST = "whitelist"  # Allow only specific file types


class FilePolicyChecker:
    """
    Checks files against configured policy rules.
    
    Features:
    - Blacklist mode: Block specific dangerous file extensions
    - Whitelist mode: Allow only approved file extensions
    - Archive scanning: Check inside .zip, .rar files
    - File size limits
    - MIME type validation (optional)
    """
    
    # Default dangerous file extensions (high-risk for malware)
    DEFAULT_BLACKLIST = [
        # Executables
        '.exe', '.msi', '.dll', '.com', '.pif', '.scr',
        # Scripts
        '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
        # Other dangerous
        '.jar', '.gadget', '.application', '.cpl', '.msc', '.hta',
        # Shortcuts (can be used for attacks)
        '.lnk', '.scf', '.inf',
        # Office macros
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm',
        # Other potentially dangerous
        '.reg', '.iso', '.img',
    ]
    
    # Default safe file extensions for whitelist mode
    DEFAULT_WHITELIST = [
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.txt', '.rtf', '.odt', '.ods', '.odp',
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico',
        # Media
        '.mp3', '.mp4', '.wav', '.avi', '.mkv', '.mov', '.wmv',
        # Archives (will be scanned if enabled)
        '.zip', '.rar', '.7z',
        # Data
        '.csv', '.json', '.xml', '.html', '.htm',
    ]
    
    def __init__(self, policy_config: Dict = None):
        """
        Initialize the File Policy Checker.
        
        Args:
            policy_config: Configuration dictionary with policy settings
        """
        config = policy_config or {}
        
        # Determine mode
        mode_str = config.get('mode', 'blacklist')
        self.mode = PolicyMode.BLACKLIST if mode_str == 'blacklist' else PolicyMode.WHITELIST
        
        # Load extension lists
        self.blacklist = set(ext.lower() for ext in config.get('blacklist', self.DEFAULT_BLACKLIST))
        self.whitelist = set(ext.lower() for ext in config.get('whitelist', self.DEFAULT_WHITELIST))
        
        # Custom additions (merged with defaults)
        custom_blacklist = config.get('custom_blacklist', [])
        custom_whitelist = config.get('custom_whitelist', [])
        self.blacklist.update(ext.lower() for ext in custom_blacklist)
        self.whitelist.update(ext.lower() for ext in custom_whitelist)
        
        # Size limits
        self.max_file_size_mb = config.get('max_file_size_mb', 100)  # 100 MB default
        self.max_file_size_bytes = self.max_file_size_mb * 1024 * 1024
        
        # Archive scanning
        self.scan_archives = config.get('scan_archives', True)
        
        # Enabled flag
        self.enabled = config.get('enabled', True)
        
        logger.info(f"File Policy Checker initialized (Mode: {self.mode.value})")
        logger.info(f"   Blacklist: {len(self.blacklist)} extensions")
        logger.info(f"   Whitelist: {len(self.whitelist)} extensions")
        logger.info(f"   Max file size: {self.max_file_size_mb} MB")
        logger.info(f"   Archive scanning: {'enabled' if self.scan_archives else 'disabled'}")
    
    def check_file(self, filename: str, file_size: int = 0) -> Tuple[bool, str, str]:
        """
        Check if a file passes policy rules.
        
        Args:
            filename: Name of the file to check
            file_size: Size of the file in bytes
            
        Returns:
            Tuple of (allowed: bool, reason: str, blocked_type: str)
            - allowed: True if file passes policy, False if blocked
            - reason: Human-readable reason
            - blocked_type: 'SIZE', 'EXTENSION', 'ARCHIVE_CONTENT', or ''
        """
        if not self.enabled:
            return True, "Policy checking disabled", ""
        
        # Get file extension
        ext = Path(filename).suffix.lower()
        
        # Check file size
        if file_size > 0 and file_size > self.max_file_size_bytes:
            size_mb = file_size / (1024 * 1024)
            reason = f"File size ({size_mb:.1f} MB) exceeds maximum allowed ({self.max_file_size_mb} MB)"
            logger.warning(f"[POLICY] Size blocked: {filename} - {reason}")
            return False, reason, "SIZE"
        
        # Check extension based on mode
        if self.mode == PolicyMode.BLACKLIST:
            if ext in self.blacklist:
                reason = f"File type '{ext}' is blocked (potentially dangerous)"
                logger.warning(f"[POLICY] Extension blocked: {filename} - {reason}")
                return False, reason, "EXTENSION"
        else:  # WHITELIST mode
            if ext and ext not in self.whitelist:
                reason = f"File type '{ext}' is not in the allowed list"
                logger.warning(f"[POLICY] Extension not whitelisted: {filename} - {reason}")
                return False, reason, "EXTENSION"
        
        return True, "File passed policy check", ""
    
    def check_file_content(self, file_path: str) -> Tuple[bool, str, str]:
        """
        Check file content, including archive contents.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            Tuple of (allowed: bool, reason: str, blocked_type: str)
        """
        if not self.enabled:
            return True, "Policy checking disabled", ""
        
        path = Path(file_path)
        
        # First, check the file itself
        try:
            file_size = path.stat().st_size
        except:
            file_size = 0
        
        allowed, reason, blocked_type = self.check_file(path.name, file_size)
        if not allowed:
            return allowed, reason, blocked_type
        
        # Magic-byte validation: check if file header matches declared extension
        magic_result = self.validate_file_magic(file_path)
        if magic_result is not None:
            allowed_magic, reason_magic = magic_result
            if not allowed_magic:
                return False, reason_magic, "MAGIC_MISMATCH"
        
        # Check archive contents if enabled
        if self.scan_archives and path.suffix.lower() == '.zip':
            return self._scan_zip_archive(file_path)
        
        return True, "File passed all policy checks", ""
    
    def _scan_zip_archive(self, file_path: str) -> Tuple[bool, str, str]:
        """
        Scan contents of a ZIP archive for blocked file types.
        
        Args:
            file_path: Path to the ZIP file
            
        Returns:
            Tuple of (allowed: bool, reason: str, blocked_type: str)
        """
        try:
            if not zipfile.is_zipfile(file_path):
                return True, "Not a valid ZIP file", ""
            
            with zipfile.ZipFile(file_path, 'r') as zf:
                for name in zf.namelist():
                    ext = Path(name).suffix.lower()
                    
                    if self.mode == PolicyMode.BLACKLIST:
                        if ext in self.blacklist:
                            reason = f"Archive contains blocked file: '{name}' (type: {ext})"
                            logger.warning(f"[POLICY] Archive content blocked: {reason}")
                            return False, reason, "ARCHIVE_CONTENT"
                    else:  # WHITELIST mode
                        if ext and ext not in self.whitelist:
                            reason = f"Archive contains non-whitelisted file: '{name}' (type: {ext})"
                            logger.warning(f"[POLICY] Archive content not whitelisted: {reason}")
                            return False, reason, "ARCHIVE_CONTENT"
            
            return True, "Archive contents passed policy check", ""
            
        except zipfile.BadZipFile:
            logger.warning(f"[POLICY] Corrupted ZIP file: {file_path}")
            return False, "Archive file appears to be corrupted", "ARCHIVE_CONTENT"
        except Exception as e:
            logger.error(f"[POLICY] Error scanning archive: {e}")
            return True, f"Could not scan archive: {str(e)}", ""
    
    def get_blocked_extensions(self) -> List[str]:
        """Get list of currently blocked extensions."""
        if self.mode == PolicyMode.BLACKLIST:
            return sorted(list(self.blacklist))
        else:
            # In whitelist mode, everything not in whitelist is blocked
            return ["All extensions not in whitelist"]
    
    def get_allowed_extensions(self) -> List[str]:
        """Get list of currently allowed extensions."""
        if self.mode == PolicyMode.WHITELIST:
            return sorted(list(self.whitelist))
        else:
            # In blacklist mode, everything not in blacklist is allowed
            return ["All extensions not in blacklist"]
    
    def is_extension_allowed(self, extension: str) -> bool:
        """
        Check if a specific extension is allowed.
        
        Args:
            extension: File extension (with or without dot)
            
        Returns:
            bool: True if allowed, False if blocked
        """
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        
        if self.mode == PolicyMode.BLACKLIST:
            return ext not in self.blacklist
        else:
            return ext in self.whitelist
    
    def validate_file_magic(self, file_path: str) -> Optional[Tuple[bool, str]]:
        """Validate file header (magic bytes) against declared extension.
        
        Uses python-magic to detect actual file type from headers and
        compares against the file extension. Catches extension spoofing
        (e.g., EXE renamed to .pdf).
        
        Returns:
            None if python-magic not available or check is inconclusive.
            (True, reason) if file type matches extension.
            (False, reason) if file type does NOT match extension.
        """
        if not MAGIC_AVAILABLE:
            return None
        
        try:
            detected_mime = magic.from_file(file_path, mime=True)
            if not detected_mime:
                return None
            
            declared_ext = Path(file_path).suffix.lower()
            
            # Check if detected MIME maps to a known dangerous set
            for mime_pattern, expected_exts in MIME_EXTENSION_MAP.items():
                if detected_mime == mime_pattern:
                    # The file IS this type — check if extension says so
                    if declared_ext not in expected_exts:
                        reason = (
                            f"File header mismatch: file declares '{declared_ext}' but "
                            f"magic bytes indicate '{detected_mime}' (expected extensions: {expected_exts})"
                        )
                        logger.warning(f"[POLICY] Magic mismatch: {file_path} - {reason}")
                        return (False, reason)
                    break
            
            return None  # No mismatch detected or unknown MIME
            
        except Exception as e:
            logger.debug(f"Magic byte check failed for {file_path}: {e}")
            return None
    
    def add_to_blacklist(self, extension: str) -> bool:
        """Add an extension to the blacklist."""
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        self.blacklist.add(ext)
        logger.info(f"[POLICY] Added '{ext}' to blacklist")
        return True
    
    def remove_from_blacklist(self, extension: str) -> bool:
        """Remove an extension from the blacklist."""
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        if ext in self.blacklist:
            self.blacklist.remove(ext)
            logger.info(f"[POLICY] Removed '{ext}' from blacklist")
            return True
        return False
    
    def add_to_whitelist(self, extension: str) -> bool:
        """Add an extension to the whitelist."""
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        self.whitelist.add(ext)
        logger.info(f"[POLICY] Added '{ext}' to whitelist")
        return True
    
    def remove_from_whitelist(self, extension: str) -> bool:
        """Remove an extension from the whitelist."""
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        if ext in self.whitelist:
            self.whitelist.remove(ext)
            logger.info(f"[POLICY] Removed '{ext}' from whitelist")
            return True
        return False
    
    def get_status(self) -> Dict:
        """Get current policy status."""
        return {
            'enabled': self.enabled,
            'mode': self.mode.value,
            'blacklist_count': len(self.blacklist),
            'whitelist_count': len(self.whitelist),
            'max_file_size_mb': self.max_file_size_mb,
            'scan_archives': self.scan_archives,
            'blacklist': sorted(list(self.blacklist)),
            'whitelist': sorted(list(self.whitelist)),
        }
    
    def get_policy_summary(self) -> str:
        """Get a human-readable policy summary."""
        if self.mode == PolicyMode.BLACKLIST:
            return f"Blocking {len(self.blacklist)} dangerous file types (e.g., .exe, .bat, .ps1)"
        else:
            return f"Allowing only {len(self.whitelist)} approved file types"


# Convenience function for creating policy checker from config module
def create_file_policy_checker():
    """Create FilePolicyChecker instance from config module."""
    try:
        import config
        policy_config = getattr(config, 'FILE_POLICY', {})
        return FilePolicyChecker(policy_config)
    except ImportError:
        logger.warning("Config module not found, using defaults")
        return FilePolicyChecker({})

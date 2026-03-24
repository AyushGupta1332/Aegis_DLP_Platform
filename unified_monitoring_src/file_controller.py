"""
File Transfer Controller Module
===============================
Controls file copy operations based on device registration status.
Implements allow/deny logic for file transfers to USB devices.

Key Features:
- Intercept file copy operations
- Verify destination against registered devices
- Allow/deny transfers based on registration
- Transfer logging and verification
- Safe file copying with progress callbacks
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Callable, Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum
import hashlib
import string

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TransferStatus(Enum):
    """Status codes for file transfer operations."""
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    CANCELLED = "CANCELLED"


@dataclass
class TransferResult:
    """Result of a file transfer operation."""
    status: TransferStatus
    source_path: str
    destination_path: str
    file_size: int
    device_hash: str
    message: str
    file_hash: Optional[str] = None


class FileTransferController:
    """
    File Transfer Controller with Device Authorization.
    
    This class provides:
    - Controlled file copy operations
    - Device registration verification
    - Transfer logging
    - Progress callbacks for GUI integration
    - File integrity verification
    
    Usage:
        controller = FileTransferController(registry, identifier)
        
        # Check if copy is allowed
        can_copy, reason = controller.can_copy_to_path("C:\\file.txt", "E:\\")
        
        # Perform controlled copy
        result = controller.copy_file("C:\\file.txt", "E:\\file.txt")
        if result.status == TransferStatus.SUCCESS:
            print("Copy successful!")
    """
    
    def __init__(self, registry, identifier):
        """
        Initialize the File Transfer Controller.
        
        Args:
            registry: DeviceRegistry instance for authorization checks
            identifier: DeviceIdentifier instance for device lookup
        """
        self.registry = registry
        self.identifier = identifier
        self._progress_callback: Optional[Callable[[int, int], None]] = None
        
        logger.info("File Transfer Controller initialized")
    
    def set_progress_callback(self, callback: Callable[[int, int], None]):
        """
        Set a callback for transfer progress updates.
        
        Args:
            callback: Function(bytes_copied, total_bytes) called during copy
        """
        self._progress_callback = callback
    
    def get_removable_drives(self) -> List[str]:
        """
        Get list of removable and USB-connected drive letters.
        
        Returns:
            List of drive letters (e.g., ['E:', 'F:'])
        
        Note: External USB HDDs may appear as 'fixed' drives (type 3) in Windows,
        so we also check for USB-connected fixed drives.
        """
        import ctypes
        
        target_drives = []
        usb_drive_letters = set()
        
        # First, get USB-connected drives via WMI (catches USB HDDs that appear as fixed)
        try:
            import wmi
            c = wmi.WMI()
            for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                        usb_drive_letters.add(logical_disk.DeviceID)
        except Exception:
            pass
        
        # Also get drives from devices detected by the identifier
        try:
            devices = self.identifier.get_connected_devices()
            for device in devices:
                if device.drive_letter:
                    usb_drive_letters.add(device.drive_letter)
        except Exception:
            pass
        
        # Check all possible drive letters
        for letter in string.ascii_uppercase:
            drive = f"{letter}:"
            drive_path = f"{drive}\\"
            
            try:
                if os.path.exists(drive_path):
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    # DRIVE_REMOVABLE = 2 (USB flash drives, SD cards)
                    # DRIVE_FIXED = 3 (includes USB HDDs which we want if USB-connected)
                    if drive_type == 2:
                        target_drives.append(drive)
                    elif drive_type == 3 and drive in usb_drive_letters:
                        # Include fixed drives that are USB-connected (external HDDs)
                        target_drives.append(drive)
            except Exception:
                pass
        
        return target_drives
    
    def get_all_non_system_drives(self) -> List[str]:
        """
        Get all non-system drives (everything except C:) for destination selection.
        
        Returns:
            List of drive letters excluding C:
        """
        import ctypes
        
        drives = set() # Use set for uniqueness
        
        # Method 1: OS Enumeration
        for letter in string.ascii_uppercase:
            if letter == 'C':  # Skip system drive
                continue
            drive = f"{letter}:"
            drive_path = f"{drive}\\"
            
            try:
                if os.path.exists(drive_path):
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    # Include removable (2) and fixed (3) drives
                    if drive_type in (2, 3):
                        drives.add(drive)
            except Exception:
                pass
        
        # Method 2: DeviceIdentifier Fallback (Critical for some external drives)
        try:
            device_drives = [d.drive_letter for d in self.identifier.get_connected_devices() if d.drive_letter]
            for d_letter in device_drives:
                if d_letter and d_letter.upper() != 'C:':
                    drives.add(d_letter)
        except Exception as e:
            logger.warning(f"Error merging device drives: {e}")
            
        result = sorted(list(drives))
        logger.info(f"Available non-system drives: {result}")
        return result
    
    def get_drive_letter(self, path: str) -> Optional[str]:
        """
        Extract drive letter from a path.
        
        Args:
            path: File or directory path
        
        Returns:
            Drive letter (e.g., "E:") or None
        """
        try:
            path_obj = Path(path).resolve()
            if path_obj.drive:
                return path_obj.drive.upper()
        except Exception:
            pass
        
        return None
    
    def is_removable_drive(self, path: str) -> bool:
        """
        Check if a path is on a removable drive.
        
        Args:
            path: Path to check
        
        Returns:
            True if path is on a removable drive
        """
        drive_letter = self.get_drive_letter(path)
        if not drive_letter:
            return False
        
        return drive_letter in self.get_removable_drives()
    
    def get_device_for_path(self, path: str):
        """
        Get the USB device associated with a path.
        
        Args:
            path: File or directory path
        
        Returns:
            USBDevice object or None
        """
        drive_letter = self.get_drive_letter(path)
        if not drive_letter:
            return None
        
        return self.identifier.get_device_by_drive_letter(drive_letter)
    
    def can_copy_to_path(self, source: str, destination: str) -> Tuple[bool, str]:
        """
        Check if a file copy to the destination is allowed.
        
        Args:
            source: Source file path
            destination: Destination path (file or directory)
        
        Returns:
            Tuple of (is_allowed: bool, reason: str)
        """
        # Validate source exists
        if not os.path.exists(source):
            return False, "Source file does not exist"
        
        # Check if destination is on a removable drive
        if not self.is_removable_drive(destination):
            # Not a removable drive - allow (only controlling USB transfers)
            return True, "Destination is not a removable drive"
        
        # Get device for destination
        device = self.get_device_for_path(destination)
        if not device:
            return False, "Cannot identify destination device"
        
        # Check registration status
        if self.registry.is_registered(device.device_hash):
            return True, f"Device '{device.friendly_name}' is registered"
        else:
            return False, f"Device '{device.friendly_name}' is NOT registered. File transfer blocked."
    
    def copy_file(self, source: str, destination: str, 
                  verify_integrity: bool = True) -> TransferResult:
        """
        Copy a file to the destination with authorization check.
        
        Args:
            source: Source file path
            destination: Destination path (file or directory)
            verify_integrity: If True, verify file hash after copy
        
        Returns:
            TransferResult with operation status
        """
        source_path = Path(source).resolve()
        dest_path = Path(destination).resolve()
        
        # If destination is a directory, append source filename
        if dest_path.is_dir() or str(destination).endswith(('/', '\\')):
            dest_path = dest_path / source_path.name
        
        # Get file size
        try:
            file_size = source_path.stat().st_size
        except Exception as e:
            return TransferResult(
                status=TransferStatus.FAILED,
                source_path=str(source_path),
                destination_path=str(dest_path),
                file_size=0,
                device_hash="",
                message=f"Cannot read source file: {e}"
            )
        
        # Check authorization
        can_copy, reason = self.can_copy_to_path(str(source_path), str(dest_path))
        
        # Get device hash for logging (use drive letter as fallback)
        device = self.get_device_for_path(str(dest_path))
        device_hash = device.device_hash if device else self.get_drive_letter(str(dest_path)) or "unknown"
        
        if not can_copy:
            # Log blocked transfer - always log
            self.registry.log_transfer(
                device_hash,
                str(source_path),
                str(dest_path),
                file_size,
                TransferStatus.BLOCKED.value
            )
            
            return TransferResult(
                status=TransferStatus.BLOCKED,
                source_path=str(source_path),
                destination_path=str(dest_path),
                file_size=file_size,
                device_hash=device_hash,
                message=reason
            )
        
        # Perform the copy
        try:
            # Ensure destination directory exists
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            if self._progress_callback:
                # Copy with progress
                self._copy_with_progress(source_path, dest_path)
            else:
                # Simple copy
                shutil.copy2(str(source_path), str(dest_path))
            
            # Verify integrity if requested
            file_hash = None
            if verify_integrity:
                source_hash = self._calculate_hash(source_path)
                dest_hash = self._calculate_hash(dest_path)
                
                if source_hash != dest_hash:
                    # Integrity check failed
                    dest_path.unlink()  # Remove corrupted copy
                    
                    # Log integrity failure - always log
                    self.registry.log_transfer(
                        device_hash,
                        str(source_path),
                        str(dest_path),
                        file_size,
                        TransferStatus.FAILED.value
                    )
                    
                    return TransferResult(
                        status=TransferStatus.FAILED,
                        source_path=str(source_path),
                        destination_path=str(dest_path),
                        file_size=file_size,
                        device_hash=device_hash,
                        message="File integrity verification failed"
                    )
                
                file_hash = source_hash
            
            # Log successful transfer - always log
            self.registry.log_transfer(
                device_hash,
                str(source_path),
                str(dest_path),
                file_size,
                TransferStatus.SUCCESS.value
            )
            
            return TransferResult(
                status=TransferStatus.SUCCESS,
                source_path=str(source_path),
                destination_path=str(dest_path),
                file_size=file_size,
                device_hash=device_hash,
                message="File copied successfully",
                file_hash=file_hash
            )
            
        except PermissionError as e:
            message = f"Permission denied: {e}"
        except OSError as e:
            message = f"OS error: {e}"
        except Exception as e:
            message = f"Copy failed: {e}"
        
        # Log failed transfer - always log
        self.registry.log_transfer(
            device_hash,
            str(source_path),
            str(dest_path),
            file_size,
            TransferStatus.FAILED.value
        )
        
        return TransferResult(
            status=TransferStatus.FAILED,
            source_path=str(source_path),
            destination_path=str(dest_path),
            file_size=file_size,
            device_hash=device_hash,
            message=message
        )
    
    def copy_files(self, sources: List[str], destination_dir: str,
                   verify_integrity: bool = True) -> List[TransferResult]:
        """
        Copy multiple files to a destination directory.
        
        Args:
            sources: List of source file paths
            destination_dir: Destination directory
            verify_integrity: If True, verify each file hash after copy
        
        Returns:
            List of TransferResult objects
        """
        results = []
        
        for source in sources:
            result = self.copy_file(source, destination_dir, verify_integrity)
            results.append(result)
        
        return results
    
    def _copy_with_progress(self, source: Path, destination: Path, 
                            buffer_size: int = 8 * 1024 * 1024):
        """
        Copy file with progress callback.
        
        Args:
            source: Source path
            destination: Destination path
            buffer_size: Buffer size for reading (default 8MB for fast transfers)
        """
        total_size = source.stat().st_size
        copied = 0
        
        with open(source, 'rb') as src_file:
            with open(destination, 'wb') as dst_file:
                while True:
                    buffer = src_file.read(buffer_size)
                    if not buffer:
                        break
                    
                    dst_file.write(buffer)
                    copied += len(buffer)
                    
                    if self._progress_callback:
                        self._progress_callback(copied, total_size)
        
        # Preserve file metadata
        shutil.copystat(str(source), str(destination))
    
    def _calculate_hash(self, file_path: Path) -> str:
        """
        Calculate SHA256 hash of a file.
        
        Args:
            file_path: Path to file
        
        Returns:
            Hex digest of file hash
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # 64KB chunks
                if not data:
                    break
                sha256.update(data)
        
        return sha256.hexdigest()
    
    def verify_file(self, source: str, destination: str) -> bool:
        """
        Verify that source and destination files are identical.
        
        Args:
            source: Source file path
            destination: Destination file path
        
        Returns:
            True if files match
        """
        try:
            source_hash = self._calculate_hash(Path(source))
            dest_hash = self._calculate_hash(Path(destination))
            return source_hash == dest_hash
        except Exception as e:
            logger.error(f"Error verifying files: {e}")
            return False


# Demonstration / Test Code
if __name__ == "__main__":
    print("=" * 60)
    print("File Transfer Controller - Test Run")
    print("=" * 60)
    
    # This requires the registry and identifier to be set up
    from device_identifier import DeviceIdentifier
    from device_registry import DeviceRegistry
    
    identifier = DeviceIdentifier()
    registry = DeviceRegistry()
    controller = FileTransferController(registry, identifier)
    
    # List removable drives
    drives = controller.get_removable_drives()
    print(f"\nRemovable drives detected: {drives}")
    
    # Show connected devices
    devices = identifier.get_connected_devices()
    print(f"\nConnected USB devices:")
    for device in devices:
        is_reg = registry.is_registered(device.device_hash)
        status = "REGISTERED" if is_reg else "NOT REGISTERED"
        print(f"  - {device.friendly_name} ({device.drive_letter}) [{status}]")
    
    print("\n" + "=" * 60)
    print("To test file copy, use:")
    print("  result = controller.copy_file('source.txt', 'E:\\\\')")
    print("=" * 60)

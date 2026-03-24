"""
Device Identifier Module
========================
Handles USB device identification using Windows Management Instrumentation (WMI).
Extracts hardware properties and generates unique device fingerprints.

Key Features:
- Enumerate all connected USB storage devices
- Extract VID, PID, Serial Number, Hardware ID
- Generate SHA256 fingerprints for unique device identification
- Support for USB drives, phones (MTP), and other removable media
"""

import wmi
import hashlib
import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class USBDevice:
    """Data class representing a USB device with all its properties."""
    vendor_id: str = ""
    product_id: str = ""
    serial_number: str = ""
    hardware_id: str = ""
    device_id: str = ""
    friendly_name: str = ""
    device_type: str = "Unknown"
    drive_letter: str = ""
    manufacturer: str = ""
    capacity: int = 0
    device_hash: str = field(default="", init=False)
    
    def __post_init__(self):
        """Generate device hash after initialization."""
        self.device_hash = self._generate_hash()
    
    def _generate_hash(self) -> str:
        """
        Generate a unique SHA256 hash combining device identifiers.
        This creates a reproducible fingerprint for the device.
        """
        # Combine multiple identifiers for robust fingerprinting
        # Include drive_letter to ensure uniqueness for logical drives
        identifier_string = f"{self.vendor_id}|{self.product_id}|{self.serial_number}|{self.hardware_id}|{self.drive_letter}"
        return hashlib.sha256(identifier_string.encode()).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert device to dictionary representation."""
        return {
            'device_hash': self.device_hash,
            'vendor_id': self.vendor_id,
            'product_id': self.product_id,
            'serial_number': self.serial_number,
            'hardware_id': self.hardware_id,
            'device_id': self.device_id,
            'friendly_name': self.friendly_name,
            'device_type': self.device_type,
            'drive_letter': self.drive_letter,
            'manufacturer': self.manufacturer,
            'capacity': self.capacity
        }


class DeviceIdentifier:
    """
    USB Device Identifier using Windows Management Instrumentation (WMI).
    
    This class provides methods to:
    - Enumerate all connected USB storage devices
    - Extract detailed hardware properties
    - Generate unique device fingerprints
    - Identify device types (USB drive, phone, etc.)
    
    Usage:
        identifier = DeviceIdentifier()
        devices = identifier.get_connected_devices()
        for device in devices:
            print(f"Device: {device.friendly_name} - Hash: {device.device_hash}")
    """
    
    # VID/PID patterns for common device types
    KNOWN_VENDORS = {
        '0781': 'SanDisk',
        '0951': 'Kingston',
        '090C': 'Silicon Motion',
        '058F': 'Alcor Micro',
        '1005': 'Apacer',
        '13FE': 'Kingston/Phison',
        '05AC': 'Apple',
        '04E8': 'Samsung',
        '22B8': 'Motorola',
        '18D1': 'Google',
        '2717': 'Xiaomi',
        '12D1': 'Huawei',
        '0BB4': 'HTC',
        '1004': 'LG',
        '2A70': 'OnePlus',
    }
    
    PHONE_VENDORS = ['05AC', '04E8', '22B8', '18D1', '2717', '12D1', '0BB4', '1004', '2A70']
    
    def __init__(self):
        """Initialize WMI connection."""
        try:
            self.wmi_service = wmi.WMI()
            logger.info("WMI connection established successfully")
        except Exception as e:
            logger.error(f"Failed to initialize WMI: {e}")
            raise RuntimeError(f"Cannot initialize WMI service: {e}")
    
    def _get_wmi(self):
        """
        Get a thread-safe WMI connection.
        WMI requires COM initialization in each thread, so we reinitialize for Flask.
        """
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except:
            pass
        try:
            return wmi.WMI()
        except Exception as e:
            logger.warning(f"Failed to get WMI connection: {e}")
            return self.wmi_service
    
    def get_connected_devices(self) -> List[USBDevice]:
        """
        Get all currently connected storage devices.
        
        Returns:
            List[USBDevice]: List of connected devices with their properties.
        """
        devices = []
        seen_drive_letters = set()
        
        try:
            # Method 1: Get ALL storage drives with drive letters (D:, E:, H:, I:, J:, etc.)
            # This is the primary source - gets all actual drives
            storage_drives = self._get_all_storage_drives()
            for dev in storage_drives:
                if dev.drive_letter:
                    seen_drive_letters.add(dev.drive_letter)
                devices.append(dev)
            
            # Method 2: Query USB disk drives for better device info
            disk_drives = self._get_usb_disk_drives()
            for dev in disk_drives:
                if dev.drive_letter and dev.drive_letter not in seen_drive_letters:
                    seen_drive_letters.add(dev.drive_letter)
                    devices.append(dev)
                elif not dev.drive_letter:
                    # USB device without drive letter (e.g., uninitialized)
                    devices.append(dev)
            
            # Method 3: Check for MTP devices (phones) - only if they have unique identifiers
            mtp_devices = self._get_mtp_devices()
            for dev in mtp_devices:
                # Skip MTP devices that are already listed as storage drives
                if dev.friendly_name in [d.friendly_name for d in devices]:
                    continue
                devices.append(dev)
            
            logger.info(f"Found {len(devices)} device(s)")
            
        except Exception as e:
            logger.error(f"Error enumerating devices: {e}")
        
        return devices
    
    def _get_usb_disk_drives(self) -> List[USBDevice]:
        """Query USB disk drives via Win32_DiskDrive - returns one device per partition."""
        devices = []
        
        try:
            # Query disk drives with USB interface
            for disk in self._get_wmi().Win32_DiskDrive(InterfaceType="USB"):
                parsed_devices = self._parse_disk_drive_all_partitions(disk)
                devices.extend(parsed_devices)
        except Exception as e:
            logger.warning(f"Error querying disk drives: {e}")
        
        return devices
    
    def _parse_disk_drive_all_partitions(self, disk) -> List[USBDevice]:
        """
        Parse a Win32_DiskDrive object into USBDevice(s) - one per partition.
        This handles multi-partition HDDs correctly.
        
        Extraction of VID/PID from PNPDeviceID:
        Format: USBSTOR\\DISK&VEN_VENDOR&PROD_PRODUCT&REV_REV\\SERIAL
        or: USB\\VID_XXXX&PID_XXXX\\SERIAL
        """
        devices = []
        try:
            pnp_device_id = disk.PNPDeviceID or ""
            serial_number = disk.SerialNumber or ""
            
            # Extract VID and PID from device ID
            vid, pid = self._extract_vid_pid(pnp_device_id)
            
            # If no VID/PID from PNPDeviceID, try to get from parent USB device
            if not vid or not pid:
                vid, pid = self._get_parent_usb_vid_pid(pnp_device_id)
            
            # Get ALL drive letter mappings for this disk
            drive_letters = self._get_drive_letters_for_disk(disk)
            
            # Determine device type
            device_type = self._determine_device_type(vid, disk.Model or "")
            
            # Get manufacturer name
            manufacturer = self.KNOWN_VENDORS.get(vid.upper(), disk.Manufacturer or "Unknown")
            
            base_name = disk.Model or disk.Caption or "USB Device"
            
            if drive_letters:
                # Create one device entry per partition/drive letter
                for drive_letter in drive_letters:
                    # Create a unique hardware ID for each partition
                    partition_hw_id = f"{pnp_device_id}#{drive_letter}"
                    
                    device = USBDevice(
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=serial_number.strip() if serial_number else "",
                        hardware_id=partition_hw_id,  # Unique per partition
                        device_id=pnp_device_id,
                        friendly_name=f"{base_name} ({drive_letter})",
                        device_type=device_type,
                        drive_letter=drive_letter,
                        manufacturer=manufacturer,
                        capacity=int(disk.Size) if disk.Size else 0
                    )
                    devices.append(device)
            else:
                # No drive letters - still add the device (e.g., uninitialized drive)
                device = USBDevice(
                    vendor_id=vid,
                    product_id=pid,
                    serial_number=serial_number.strip() if serial_number else "",
                    hardware_id=pnp_device_id,
                    device_id=pnp_device_id,
                    friendly_name=base_name,
                    device_type=device_type,
                    drive_letter="",
                    manufacturer=manufacturer,
                    capacity=int(disk.Size) if disk.Size else 0
                )
                devices.append(device)
            
        except Exception as e:
            logger.warning(f"Error parsing disk drive: {e}")
        
        return devices
    
    def _parse_disk_drive(self, disk) -> Optional[USBDevice]:
        """
        Parse a Win32_DiskDrive object into a USBDevice (backward compatibility).
        Returns only the first partition.
        """
        devices = self._parse_disk_drive_all_partitions(disk)
        return devices[0] if devices else None
    
    def _extract_vid_pid(self, device_id: str) -> tuple:
        """
        Extract Vendor ID and Product ID from device identification string.
        
        Handles multiple formats:
        - USB\\VID_XXXX&PID_XXXX\\...
        - USBSTOR\\DISK&VEN_XXX&PROD_XXX\\...
        """
        vid = ""
        pid = ""
        
        # Pattern 1: USB\VID_XXXX&PID_XXXX
        vid_match = re.search(r'VID_([0-9A-Fa-f]{4})', device_id)
        pid_match = re.search(r'PID_([0-9A-Fa-f]{4})', device_id)
        
        if vid_match:
            vid = vid_match.group(1).upper()
        if pid_match:
            pid = pid_match.group(1).upper()
        
        # Pattern 2: USBSTOR format - extract from vendor/product strings
        if not vid:
            ven_match = re.search(r'VEN_([^&]+)', device_id)
            if ven_match:
                vid = ven_match.group(1)[:4].upper()
        
        if not pid:
            prod_match = re.search(r'PROD_([^&]+)', device_id)
            if prod_match:
                pid = prod_match.group(1)[:4].upper()
        
        return vid, pid
    
    def _get_parent_usb_vid_pid(self, device_id: str) -> tuple:
        """Get VID/PID from parent USB controller device."""
        try:
            # Query USB controller entities
            for usb in self._get_wmi().Win32_USBControllerDevice():
                dependent = usb.Dependent
                if device_id.lower() in str(dependent).lower():
                    antecedent = str(usb.Antecedent)
                    return self._extract_vid_pid(antecedent)
        except Exception as e:
            logger.debug(f"Could not get parent USB info: {e}")
        
        return "", ""
    
    def _get_drive_letters_for_disk(self, disk) -> List[str]:
        """Map a physical disk to ALL its logical drive letters (for multi-partition drives)."""
        drive_letters = []
        try:
            # Navigate: DiskDrive -> Partition -> LogicalDisk
            for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    drive_letters.append(logical_disk.DeviceID)  # e.g., "E:"
        except Exception as e:
            logger.debug(f"Could not map drive letters: {e}")
        
        return drive_letters
    
    def _get_drive_letter_for_disk(self, disk) -> str:
        """Map a physical disk to its first logical drive letter (for backward compatibility)."""
        letters = self._get_drive_letters_for_disk(disk)
        return letters[0] if letters else ""
    
    def _get_removable_drives(self) -> List[USBDevice]:
        """Get removable drives via Win32_LogicalDisk."""
        devices = []
        
        try:
            # DriveType 2 = Removable disk
            for disk in self._get_wmi().Win32_LogicalDisk(DriveType=2):
                device = USBDevice(
                    drive_letter=disk.DeviceID,
                    friendly_name=disk.VolumeName or f"Removable ({disk.DeviceID})",
                    device_type="Removable Drive",
                    capacity=int(disk.Size) if disk.Size else 0
                )
                devices.append(device)
        except Exception as e:
            logger.warning(f"Error querying removable drives: {e}")
        
        return devices
    
    def _get_all_storage_drives(self) -> List[USBDevice]:
        """
        Get ALL storage drives (except C:) with proper drive letters.
        This includes internal drives, external HDDs, and USB drives.
        """
        devices = []
        
        try:
            for disk in self._get_wmi().Win32_LogicalDisk():
                # Skip system drive and non-storage types
                if disk.DeviceID == "C:":
                    continue
                drive_type = disk.DriveType
                # 2 = Removable, 3 = Fixed (includes external HDDs)
                if drive_type not in (2, 3):
                    continue
                    
                # Determine device type based on drive type
                if drive_type == 2:
                    dev_type = "Removable Drive"
                else:
                    dev_type = "Fixed Drive"
                
                device = USBDevice(
                    drive_letter=disk.DeviceID,
                    friendly_name=disk.VolumeName or f"Drive ({disk.DeviceID})",
                    device_type=dev_type,
                    capacity=int(disk.Size) if disk.Size else 0
                )
                devices.append(device)
        except Exception as e:
            logger.warning(f"Error querying storage drives: {e}")
        
        return devices
    
    def _merge_device_info(self, primary: List[USBDevice], secondary: List[USBDevice]) -> List[USBDevice]:
        """Merge device information from multiple sources, avoiding duplicates."""
        merged = {d.device_hash: d for d in primary if d.device_hash}
        
        for sec_device in secondary:
            # Try to match by drive letter
            matched = False
            for hash_key, prim_device in merged.items():
                if prim_device.drive_letter == sec_device.drive_letter:
                    # Update with any missing info
                    if not prim_device.friendly_name and sec_device.friendly_name:
                        prim_device.friendly_name = sec_device.friendly_name
                    matched = True
                    break
            
            if not matched and sec_device.drive_letter:
                # Add as new device if has meaningful identifier
                sec_device.device_hash = sec_device._generate_hash()
                if sec_device.device_hash:
                    merged[sec_device.device_hash] = sec_device
        
        return list(merged.values())
    
    def _get_mtp_devices(self) -> List[USBDevice]:
        """
        Detect MTP (Media Transfer Protocol) devices like smartphones.
        These appear as WPD (Windows Portable Devices) rather than disk drives.
        """
        devices = []
        
        try:
            # Query PnP entities for portable devices
            for entity in self._get_wmi().Win32_PnPEntity():
                if entity.PNPClass and 'WPD' in entity.PNPClass:
                    pnp_id = entity.PNPDeviceID or ""
                    vid, pid = self._extract_vid_pid(pnp_id)
                    
                    device = USBDevice(
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=self._extract_serial_from_pnp(pnp_id),
                        hardware_id=pnp_id,
                        device_id=pnp_id,
                        friendly_name=entity.Caption or entity.Name or "Portable Device",
                        device_type="MTP Device (Phone/Camera)",
                        manufacturer=self.KNOWN_VENDORS.get(vid.upper(), entity.Manufacturer or "Unknown")
                    )
                    devices.append(device)
                    
        except Exception as e:
            logger.debug(f"Error querying MTP devices: {e}")
        
        return devices
    
    def _extract_serial_from_pnp(self, pnp_id: str) -> str:
        """Extract serial number from PnP device ID (usually last segment)."""
        parts = pnp_id.split('\\')
        if len(parts) >= 3:
            return parts[-1]
        return ""
    
    def _determine_device_type(self, vid: str, model: str) -> str:
        """Determine device type based on VID and model string."""
        vid_upper = vid.upper()
        model_lower = model.lower()
        
        if vid_upper in self.PHONE_VENDORS:
            return "Mobile Phone"
        
        if any(keyword in model_lower for keyword in ['phone', 'mobile', 'android', 'iphone']):
            return "Mobile Phone"
        
        if any(keyword in model_lower for keyword in ['flash', 'usb', 'cruzer', 'datatraveler']):
            return "USB Flash Drive"
        
        if any(keyword in model_lower for keyword in ['hdd', 'hard', 'external']):
            return "External HDD"
        
        if any(keyword in model_lower for keyword in ['ssd', 'solid']):
            return "External SSD"
        
        return "USB Storage"
    
    def get_device_by_drive_letter(self, drive_letter: str) -> Optional[USBDevice]:
        """
        Find a specific device by its drive letter.
        
        Args:
            drive_letter: Drive letter to search for (e.g., "E:" or "E")
        
        Returns:
            USBDevice if found, None otherwise
        """
        # Normalize drive letter
        if not drive_letter.endswith(':'):
            drive_letter = drive_letter + ':'
        
        devices = self.get_connected_devices()
        for device in devices:
            if device.drive_letter.upper() == drive_letter.upper():
                return device
        
        return None
    
    def get_device_by_hash(self, device_hash: str) -> Optional[USBDevice]:
        """
        Find a connected device by its hash.
        
        Args:
            device_hash: SHA256 hash of the device to find
        
        Returns:
            USBDevice if found and connected, None otherwise
        """
        devices = self.get_connected_devices()
        for device in devices:
            if device.device_hash == device_hash:
                return device
        
        return None
    
    def refresh(self) -> List[USBDevice]:
        """Refresh and return the current list of connected devices."""
        return self.get_connected_devices()


# Demonstration / Test Code
if __name__ == "__main__":
    print("=" * 60)
    print("USB Device Identifier - Test Run")  
    print("=" * 60)
    
    identifier = DeviceIdentifier()
    devices = identifier.get_connected_devices()
    
    if not devices:
        print("\nNo USB devices detected.")
    else:
        for i, device in enumerate(devices, 1):
            print(f"\n--- Device {i} ---")
            print(f"  Name:         {device.friendly_name}")
            print(f"  Type:         {device.device_type}")
            print(f"  Manufacturer: {device.manufacturer}")
            print(f"  VID:          {device.vendor_id}")
            print(f"  PID:          {device.product_id}")
            print(f"  Serial:       {device.serial_number}")
            print(f"  Drive Letter: {device.drive_letter}")
            print(f"  Hash:         {device.device_hash[:16]}...")
            if device.capacity:
                print(f"  Capacity:     {device.capacity / (1024**3):.2f} GB")

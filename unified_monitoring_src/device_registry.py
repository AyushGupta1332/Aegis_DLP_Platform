"""
Device Registry Module
======================
Manages device registration and persistence using SQLite database.
Provides CRUD operations for authorized USB devices.

Key Features:
- SQLite database for persistent storage
- Register/unregister devices with full metadata
- Query registration status by device hash
- Transfer logging for audit trails
- Automatic database initialization
"""

import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from contextlib import contextmanager
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RegisteredDevice:
    """Represents a device record from the database."""
    id: int
    device_hash: str
    vendor_id: str
    product_id: str
    serial_number: str
    hardware_id: str
    friendly_name: str
    device_type: str
    drive_letter: str
    registered_at: str
    last_seen: str
    is_active: bool


@dataclass
class TransferLog:
    """Represents a file transfer log entry."""
    id: int
    device_hash: str
    source_path: str
    destination_path: str
    file_size: int
    transfer_status: str
    timestamp: str


class DeviceRegistry:
    """
    Device Registration System using SQLite database.
    
    This class provides:
    - Persistent storage of registered/authorized devices
    - CRUD operations for device management
    - Transfer logging for audit purposes
    - Query methods for registration verification
    
    Usage:
        registry = DeviceRegistry()
        
        # Register a device
        registry.register_device(device_info)
        
        # Check if device is authorized
        if registry.is_registered(device_hash):
            print("Device is authorized")
    """
    
    # SQL Schema definitions
    SCHEMA_DEVICES = """
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_hash TEXT UNIQUE NOT NULL,
            vendor_id TEXT NOT NULL,
            product_id TEXT NOT NULL,
            serial_number TEXT,
            hardware_id TEXT,
            friendly_name TEXT,
            device_type TEXT,
            drive_letter TEXT,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    """
    
    SCHEMA_TRANSFER_LOGS = """
        CREATE TABLE IF NOT EXISTS transfer_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_hash TEXT,
            source_path TEXT,
            destination_path TEXT,
            file_size INTEGER,
            transfer_status TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_hash) REFERENCES devices(device_hash)
        )
    """
    
    SCHEMA_INDICES = [
        "CREATE INDEX IF NOT EXISTS idx_device_hash ON devices(device_hash)",
        "CREATE INDEX IF NOT EXISTS idx_transfer_device ON transfer_logs(device_hash)",
        "CREATE INDEX IF NOT EXISTS idx_transfer_timestamp ON transfer_logs(timestamp)"
    ]
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the Device Registry.
        
        Args:
            db_path: Path to SQLite database file. If None, uses default location.
        """
        if db_path is None:
            # Default database location
            base_path = Path(__file__).parent.parent / "databases" / "unified_monitoring"
            base_path.mkdir(parents=True, exist_ok=True)
            self.db_path = base_path / "devices.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_database()
        logger.info(f"Device Registry initialized at: {self.db_path}")
    
    def _init_database(self):
        """Initialize database schema if not exists."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute(self.SCHEMA_DEVICES)
            cursor.execute(self.SCHEMA_TRANSFER_LOGS)
            
            # Create indices
            for index_sql in self.SCHEMA_INDICES:
                cursor.execute(index_sql)
            
            conn.commit()
            logger.debug("Database schema initialized")
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def register_device(self, device_info: Dict) -> Tuple[bool, str]:
        """
        Register a new device in the database.
        
        Args:
            device_info: Dictionary containing device properties:
                - device_hash (required)
                - vendor_id, product_id, serial_number
                - hardware_id, friendly_name, device_type
                - drive_letter
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        device_hash = device_info.get('device_hash')
        if not device_hash:
            return False, "Device hash is required"
        
        # Check if already registered
        if self.is_registered(device_hash):
            # Update last_seen timestamp
            self.update_last_seen(device_hash)
            return True, "Device already registered, updated last seen"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO devices (
                        device_hash, vendor_id, product_id, serial_number,
                        hardware_id, friendly_name, device_type, drive_letter,
                        registered_at, last_seen, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_hash,
                    device_info.get('vendor_id', ''),
                    device_info.get('product_id', ''),
                    device_info.get('serial_number', ''),
                    device_info.get('hardware_id', ''),
                    device_info.get('friendly_name', 'Unknown Device'),
                    device_info.get('device_type', 'USB Storage'),
                    device_info.get('drive_letter', ''),
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    True
                ))
                
                conn.commit()
                logger.info(f"Device registered: {device_info.get('friendly_name', device_hash[:16])}")
                return True, "Device registered successfully"
                
        except sqlite3.IntegrityError as e:
            logger.warning(f"Integrity error registering device: {e}")
            return False, f"Device registration failed: {e}"
        except Exception as e:
            logger.error(f"Error registering device: {e}")
            return False, f"Registration error: {e}"
    
    def unregister_device(self, device_hash: str, soft_delete: bool = True) -> Tuple[bool, str]:
        """
        Unregister a device from the database.
        
        Args:
            device_hash: Hash of the device to unregister
            soft_delete: If True, marks device as inactive. If False, deletes record.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_registered(device_hash, include_inactive=True):
            return False, "Device not found in registry"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if soft_delete:
                    cursor.execute(
                        "UPDATE devices SET is_active = 0 WHERE device_hash = ?",
                        (device_hash,)
                    )
                    message = "Device deactivated"
                else:
                    cursor.execute(
                        "DELETE FROM devices WHERE device_hash = ?",
                        (device_hash,)
                    )
                    message = "Device deleted from registry"
                
                conn.commit()
                logger.info(f"Device unregistered: {device_hash[:16]}...")
                return True, message
                
        except Exception as e:
            logger.error(f"Error unregistering device: {e}")
            return False, f"Unregistration error: {e}"
    
    def is_registered(self, device_hash: str, include_inactive: bool = False) -> bool:
        """
        Check if a device is registered and active.
        
        Args:
            device_hash: Hash of the device to check
            include_inactive: If True, returns True for inactive devices too
        
        Returns:
            True if device is registered (and active, unless include_inactive is True)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if include_inactive:
                    cursor.execute(
                        "SELECT 1 FROM devices WHERE device_hash = ?",
                        (device_hash,)
                    )
                else:
                    cursor.execute(
                        "SELECT 1 FROM devices WHERE device_hash = ? AND is_active = 1",
                        (device_hash,)
                    )
                
                return cursor.fetchone() is not None
                
        except Exception as e:
            logger.error(f"Error checking registration: {e}")
            return False
    
    def get_device(self, device_hash: str) -> Optional[RegisteredDevice]:
        """
        Get a registered device by its hash.
        
        Args:
            device_hash: Hash of the device to retrieve
        
        Returns:
            RegisteredDevice object or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM devices WHERE device_hash = ?",
                    (device_hash,)
                )
                row = cursor.fetchone()
                
                if row:
                    return RegisteredDevice(
                        id=row['id'],
                        device_hash=row['device_hash'],
                        vendor_id=row['vendor_id'],
                        product_id=row['product_id'],
                        serial_number=row['serial_number'],
                        hardware_id=row['hardware_id'],
                        friendly_name=row['friendly_name'],
                        device_type=row['device_type'],
                        drive_letter=row['drive_letter'],
                        registered_at=row['registered_at'],
                        last_seen=row['last_seen'],
                        is_active=bool(row['is_active'])
                    )
                return None
                
        except Exception as e:
            logger.error(f"Error getting device: {e}")
            return None
    
    def get_all_devices(self, active_only: bool = True) -> List[RegisteredDevice]:
        """
        Get all registered devices.
        
        Args:
            active_only: If True, only returns active devices
        
        Returns:
            List of RegisteredDevice objects
        """
        devices = []
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if active_only:
                    cursor.execute("SELECT * FROM devices WHERE is_active = 1 ORDER BY registered_at DESC")
                else:
                    cursor.execute("SELECT * FROM devices ORDER BY registered_at DESC")
                
                for row in cursor.fetchall():
                    devices.append(RegisteredDevice(
                        id=row['id'],
                        device_hash=row['device_hash'],
                        vendor_id=row['vendor_id'],
                        product_id=row['product_id'],
                        serial_number=row['serial_number'],
                        hardware_id=row['hardware_id'],
                        friendly_name=row['friendly_name'],
                        device_type=row['device_type'],
                        drive_letter=row['drive_letter'],
                        registered_at=row['registered_at'],
                        last_seen=row['last_seen'],
                        is_active=bool(row['is_active'])
                    ))
                    
        except Exception as e:
            logger.error(f"Error getting all devices: {e}")
        
        return devices
    
    def update_last_seen(self, device_hash: str, drive_letter: Optional[str] = None) -> bool:
        """
        Update the last_seen timestamp for a device.
        
        Args:
            device_hash: Hash of the device to update
            drive_letter: Optionally update drive letter as well
        
        Returns:
            True if update successful
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if drive_letter:
                    cursor.execute(
                        "UPDATE devices SET last_seen = ?, drive_letter = ? WHERE device_hash = ?",
                        (datetime.now().isoformat(), drive_letter, device_hash)
                    )
                else:
                    cursor.execute(
                        "UPDATE devices SET last_seen = ? WHERE device_hash = ?",
                        (datetime.now().isoformat(), device_hash)
                    )
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error updating last seen: {e}")
            return False
    
    def log_transfer(self, device_hash: str, source_path: str, 
                     destination_path: str, file_size: int, 
                     status: str) -> bool:
        """
        Log a file transfer operation.
        
        Args:
            device_hash: Hash of the target device
            source_path: Source file path
            destination_path: Destination file path
            file_size: Size of the file in bytes
            status: Transfer status ('SUCCESS', 'BLOCKED', 'FAILED')
        
        Returns:
            True if logging successful
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO transfer_logs (
                        device_hash, source_path, destination_path,
                        file_size, transfer_status, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    device_hash,
                    source_path,
                    destination_path,
                    file_size,
                    status,
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                logger.debug(f"Transfer logged: {status} - {source_path}")
                return True
                
        except Exception as e:
            logger.error(f"Error logging transfer: {e}")
            return False
    
    def get_transfer_logs(self, device_hash: Optional[str] = None, 
                          limit: int = 100) -> List[TransferLog]:
        """
        Get transfer logs, optionally filtered by device.
        
        Args:
            device_hash: If provided, filter by this device
            limit: Maximum number of records to return
        
        Returns:
            List of TransferLog objects
        """
        logs = []
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if device_hash:
                    cursor.execute(
                        "SELECT * FROM transfer_logs WHERE device_hash = ? ORDER BY timestamp DESC LIMIT ?",
                        (device_hash, limit)
                    )
                else:
                    cursor.execute(
                        "SELECT * FROM transfer_logs ORDER BY timestamp DESC LIMIT ?",
                        (limit,)
                    )
                
                for row in cursor.fetchall():
                    logs.append(TransferLog(
                        id=row['id'],
                        device_hash=row['device_hash'],
                        source_path=row['source_path'],
                        destination_path=row['destination_path'],
                        file_size=row['file_size'],
                        transfer_status=row['transfer_status'],
                        timestamp=row['timestamp']
                    ))
                    
        except Exception as e:
            logger.error(f"Error getting transfer logs: {e}")
        
        return logs
    
    def get_statistics(self) -> Dict:
        """
        Get registry statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_devices': 0,
            'active_devices': 0,
            'total_transfers': 0,
            'successful_transfers': 0,
            'blocked_transfers': 0,
            'failed_transfers': 0
        }
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Device counts
                cursor.execute("SELECT COUNT(*) FROM devices")
                stats['total_devices'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM devices WHERE is_active = 1")
                stats['active_devices'] = cursor.fetchone()[0]
                
                # Transfer counts
                cursor.execute("SELECT COUNT(*) FROM transfer_logs")
                stats['total_transfers'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM transfer_logs WHERE transfer_status = 'SUCCESS'")
                stats['successful_transfers'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM transfer_logs WHERE transfer_status = 'BLOCKED'")
                stats['blocked_transfers'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM transfer_logs WHERE transfer_status = 'FAILED'")
                stats['failed_transfers'] = cursor.fetchone()[0]
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
        
        return stats


# Demonstration / Test Code
if __name__ == "__main__":
    print("=" * 60)
    print("Device Registry - Test Run")
    print("=" * 60)
    
    # Create registry
    registry = DeviceRegistry()
    
    # Test data
    test_device = {
        'device_hash': 'abc123def456',
        'vendor_id': '0781',
        'product_id': '5567',
        'serial_number': 'TEST123',
        'hardware_id': 'USB\\VID_0781&PID_5567',
        'friendly_name': 'Test USB Drive',
        'device_type': 'USB Flash Drive',
        'drive_letter': 'E:'
    }
    
    # Register device
    success, message = registry.register_device(test_device)
    print(f"\nRegister: {message}")
    
    # Check registration
    is_reg = registry.is_registered('abc123def456')
    print(f"Is registered: {is_reg}")
    
    # Get all devices
    devices = registry.get_all_devices()
    print(f"\nRegistered devices: {len(devices)}")
    for d in devices:
        print(f"  - {d.friendly_name} ({d.device_hash[:16]}...)")
    
    # Log a transfer
    registry.log_transfer('abc123def456', 'C:\\test.txt', 'E:\\test.txt', 1024, 'SUCCESS')
    
    # Get statistics
    stats = registry.get_statistics()
    print(f"\nStatistics: {stats}")

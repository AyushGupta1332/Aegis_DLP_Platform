"""
USB Monitor Module
==================
Real-time USB device insertion/removal monitoring using WMI events.
Implements callback mechanisms for device connection/disconnection.

Key Features:
- Background thread for continuous monitoring
- WMI event subscription for device changes
- Callback mechanisms for insertion/removal events
- Thread-safe event handling
- Integration with device identifier and registry
"""

import threading
import queue
import time
import logging
from typing import Callable, Optional, List
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

import pythoncom
import wmi

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class USBEventType(Enum):
    """Types of USB device events."""
    INSERTED = "inserted"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass
class USBEvent:
    """Represents a USB device event."""
    event_type: USBEventType
    device_id: str
    description: str
    timestamp: datetime
    raw_data: dict


class USBMonitor:
    """
    Real-Time USB Device Monitor using WMI Events.
    
    This class provides:
    - Background monitoring for USB device changes
    - Event callbacks for device insertion/removal
    - Thread-safe event queue for GUI integration
    - Automatic device identification on connection
    
    Usage:
        def on_device_inserted(event):
            print(f"Device connected: {event.description}")
        
        def on_device_removed(event):
            print(f"Device removed: {event.description}")
        
        monitor = USBMonitor()
        monitor.add_callback(USBEventType.INSERTED, on_device_inserted)
        monitor.add_callback(USBEventType.REMOVED, on_device_removed)
        monitor.start()
        
        # ... application runs ...
        
        monitor.stop()
    """
    
    # WMI queries for device events
    QUERY_CREATION = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'"
    QUERY_DELETION = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'"
    QUERY_DISK_CREATION = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_DiskDrive'"
    QUERY_DISK_DELETION = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_DiskDrive'"
    
    def __init__(self, poll_interval: float = 2.0):
        """
        Initialize the USB Monitor.
        
        Args:
            poll_interval: Interval in seconds for WMI polling (default 2.0)
        """
        self.poll_interval = poll_interval
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._callbacks: dict = {
            USBEventType.INSERTED: [],
            USBEventType.REMOVED: [],
            USBEventType.MODIFIED: []
        }
        self._event_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        
        # Track known devices to detect changes
        self._known_devices: set = set()
        
        logger.info("USB Monitor initialized")
    
    def add_callback(self, event_type: USBEventType, callback: Callable[[USBEvent], None]):
        """
        Register a callback for a specific event type.
        
        Args:
            event_type: Type of event to listen for
            callback: Function to call when event occurs
        """
        with self._lock:
            if callback not in self._callbacks[event_type]:
                self._callbacks[event_type].append(callback)
                logger.debug(f"Callback registered for {event_type.value}")
    
    def remove_callback(self, event_type: USBEventType, callback: Callable[[USBEvent], None]):
        """
        Remove a registered callback.
        
        Args:
            event_type: Type of event
            callback: Function to remove
        """
        with self._lock:
            if callback in self._callbacks[event_type]:
                self._callbacks[event_type].remove(callback)
                logger.debug(f"Callback removed for {event_type.value}")
    
    def start(self):
        """Start the background monitoring thread."""
        if self._running:
            logger.warning("Monitor is already running")
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="USBMonitorThread",
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("USB Monitor started")
    
    def stop(self):
        """Stop the monitoring thread."""
        if not self._running:
            return
        
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None
        logger.info("USB Monitor stopped")
    
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._running
    
    def get_pending_events(self) -> List[USBEvent]:
        """
        Get all pending events from the queue (non-blocking).
        Useful for GUI polling integration.
        
        Returns:
            List of pending USBEvent objects
        """
        events = []
        while True:
            try:
                event = self._event_queue.get_nowait()
                events.append(event)
            except queue.Empty:
                break
        return events
    
    def _monitor_loop(self):
        """Main monitoring loop running in background thread."""
        # Initialize COM for this thread
        pythoncom.CoInitialize()
        
        try:
            # Create WMI connection in this thread
            wmi_service = wmi.WMI()
            
            # Initialize known devices
            self._init_known_devices(wmi_service)
            
            # Create watchers for different event types
            usb_creation_watcher = wmi_service.watch_for(
                raw_wql=self.QUERY_CREATION
            )
            usb_deletion_watcher = wmi_service.watch_for(
                raw_wql=self.QUERY_DELETION
            )
            disk_creation_watcher = wmi_service.watch_for(
                raw_wql=self.QUERY_DISK_CREATION
            )
            disk_deletion_watcher = wmi_service.watch_for(
                raw_wql=self.QUERY_DISK_DELETION
            )
            
            logger.info("WMI event watchers started")
            
            while self._running:
                try:
                    # Check USB Hub events (non-blocking with timeout)
                    self._check_watcher(usb_creation_watcher, USBEventType.INSERTED, "USB Hub")
                    self._check_watcher(usb_deletion_watcher, USBEventType.REMOVED, "USB Hub")
                    
                    # Check Disk Drive events
                    self._check_watcher(disk_creation_watcher, USBEventType.INSERTED, "Disk Drive")
                    self._check_watcher(disk_deletion_watcher, USBEventType.REMOVED, "Disk Drive")
                    
                    # Also poll for changes in removable drives
                    self._poll_removable_drives(wmi_service)
                    
                    time.sleep(0.5)  # Small sleep to prevent CPU spinning
                    
                except Exception as e:
                    if self._running:  # Only log if not shutting down
                        logger.warning(f"Error in monitor loop: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"Fatal error in monitor thread: {e}")
        finally:
            pythoncom.CoUninitialize()
    
    def _init_known_devices(self, wmi_service):
        """Initialize the set of known devices."""
        try:
            for disk in wmi_service.Win32_LogicalDisk(DriveType=2):
                self._known_devices.add(disk.DeviceID)
            logger.debug(f"Initialized with {len(self._known_devices)} known devices")
        except Exception as e:
            logger.warning(f"Error initializing known devices: {e}")
    
    def _check_watcher(self, watcher, event_type: USBEventType, source: str):
        """Check a watcher for new events (non-blocking)."""
        try:
            # Try to get event with short timeout
            event_data = watcher(timeout_ms=100)
            if event_data:
                self._process_wmi_event(event_data, event_type, source)
        except wmi.x_wmi_timed_out:
            pass  # No event, this is normal
        except Exception as e:
            if self._running:
                logger.debug(f"Watcher check error: {e}")
    
    def _process_wmi_event(self, wmi_event, event_type: USBEventType, source: str):
        """Process a WMI event and dispatch callbacks."""
        try:
            target = wmi_event.TargetInstance
            device_id = getattr(target, 'DeviceID', '') or getattr(target, 'PNPDeviceID', '')
            description = getattr(target, 'Description', '') or getattr(target, 'Caption', source)
            
            # Create event object
            event = USBEvent(
                event_type=event_type,
                device_id=str(device_id),
                description=str(description),
                timestamp=datetime.now(),
                raw_data={
                    'source': source,
                    'device_id': str(device_id),
                    'description': str(description)
                }
            )
            
            logger.info(f"USB Event: {event_type.value} - {description}")
            
            # Queue event for GUI
            self._event_queue.put(event)
            
            # Dispatch callbacks
            self._dispatch_callbacks(event)
            
        except Exception as e:
            logger.warning(f"Error processing WMI event: {e}")
    
    def _poll_removable_drives(self, wmi_service):
        """Poll for changes in removable drives (backup detection method)."""
        try:
            current_drives = set()
            for disk in wmi_service.Win32_LogicalDisk(DriveType=2):
                current_drives.add(disk.DeviceID)
            
            # Detect new drives
            new_drives = current_drives - self._known_devices
            for drive in new_drives:
                event = USBEvent(
                    event_type=USBEventType.INSERTED,
                    device_id=drive,
                    description=f"Removable Drive ({drive})",
                    timestamp=datetime.now(),
                    raw_data={'drive_letter': drive}
                )
                logger.info(f"Drive detected: {drive}")
                self._event_queue.put(event)
                self._dispatch_callbacks(event)
            
            # Detect removed drives
            removed_drives = self._known_devices - current_drives
            for drive in removed_drives:
                event = USBEvent(
                    event_type=USBEventType.REMOVED,
                    device_id=drive,
                    description=f"Removable Drive ({drive})",
                    timestamp=datetime.now(),
                    raw_data={'drive_letter': drive}
                )
                logger.info(f"Drive removed: {drive}")
                self._event_queue.put(event)
                self._dispatch_callbacks(event)
            
            # Update known devices
            self._known_devices = current_drives
            
        except Exception as e:
            logger.debug(f"Error polling removable drives: {e}")
    
    def _dispatch_callbacks(self, event: USBEvent):
        """Dispatch event to registered callbacks."""
        with self._lock:
            callbacks = self._callbacks.get(event.event_type, []).copy()
        
        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in callback: {e}")


class USBMonitorWithRegistry(USBMonitor):
    """
    Extended USB Monitor that integrates with Device Registry.
    
    Automatically checks registration status when devices connect.
    """
    
    def __init__(self, registry, identifier, poll_interval: float = 2.0):
        """
        Initialize monitor with registry and identifier.
        
        Args:
            registry: DeviceRegistry instance
            identifier: DeviceIdentifier instance
            poll_interval: WMI polling interval
        """
        super().__init__(poll_interval)
        self.registry = registry
        self.identifier = identifier
        
        # Add internal callback for registration check
        self.add_callback(USBEventType.INSERTED, self._on_device_inserted)
    
    def _on_device_inserted(self, event: USBEvent):
        """Handle device insertion - check registration status."""
        try:
            # Give the system a moment to fully recognize the device
            time.sleep(1.0)
            
            # Refresh device list
            devices = self.identifier.get_connected_devices()
            
            for device in devices:
                is_registered = self.registry.is_registered(device.device_hash)
                
                # Update last seen if registered
                if is_registered:
                    self.registry.update_last_seen(
                        device.device_hash, 
                        device.drive_letter
                    )
                    logger.info(f"Registered device connected: {device.friendly_name}")
                else:
                    logger.warning(f"UNREGISTERED device connected: {device.friendly_name}")
                    
        except Exception as e:
            logger.error(f"Error checking device registration: {e}")


# Demonstration / Test Code
if __name__ == "__main__":
    print("=" * 60)
    print("USB Monitor - Test Run")
    print("=" * 60)
    print("Monitoring USB events. Insert or remove a USB device...")
    print("Press Ctrl+C to stop.\n")
    
    def on_insert(event):
        print(f"[+] INSERTED: {event.description}")
        print(f"    Device ID: {event.device_id}")
        print(f"    Time: {event.timestamp}")
    
    def on_remove(event):
        print(f"[-] REMOVED: {event.description}")
        print(f"    Device ID: {event.device_id}")
        print(f"    Time: {event.timestamp}")
    
    monitor = USBMonitor()
    monitor.add_callback(USBEventType.INSERTED, on_insert)
    monitor.add_callback(USBEventType.REMOVED, on_remove)
    
    try:
        monitor.start()
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Done.")

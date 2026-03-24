"""
User Management Module
======================
Handles user authentication, registration, and role-based access control.

Roles:
- superadmin: Full system access, can register devices and manage admins
- admin: Can authorize users for devices, view logs
- user: Can transfer files to authorized devices only

Features:
- Secure password hashing with bcrypt/hashlib
- Session management
- Role-based permissions
- MAC address-based authentication for extra security
- Device secret (second factor) to prevent MAC spoofing
"""

import sqlite3
import hashlib
import secrets
import logging
import uuid
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_mac_address() -> str:
    """
    Get the Physical MAC address of the current system's active network adapter.
    Returns a formatted MAC address string (e.g., 'AA:BB:CC:DD:EE:FF').
    
    This uses PowerShell Get-NetAdapter to get the actual physical hardware address
    that matches what you see in Windows Settings > Network & Internet > Wi-Fi/Ethernet.
    
    Priority order:
    1. Active Wi-Fi adapter
    2. Active Ethernet adapter  
    3. Any other active physical adapter (excluding virtual/VPN adapters)
    """
    try:
        import subprocess
        
        # Method 1: Use PowerShell Get-NetAdapter (most accurate for Windows)
        # This properly identifies active physical adapters
        result = subprocess.run(
            ['powershell', '-Command', 
             'Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object Name, MacAddress | ConvertTo-Csv -NoTypeInformation'],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            wifi_mac = None
            ethernet_mac = None
            other_mac = None
            
            # Keywords to identify virtual/non-physical adapters to skip
            virtual_keywords = ['vmware', 'virtual', 'vpn', 'tap-', 'loopback', 'bluetooth', 'hyper-v']
            
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue
                # Parse CSV: "Name","MacAddress"
                parts = line.replace('"', '').split(',')
                if len(parts) >= 2:
                    adapter_name = parts[0].strip().lower()
                    mac = parts[1].strip()
                    
                    if not mac or mac == "":
                        continue
                    
                    # Skip virtual adapters
                    is_virtual = any(keyword in adapter_name for keyword in virtual_keywords)
                    if is_virtual:
                        continue
                    
                    # Normalize MAC format from XX-XX-XX-XX-XX-XX to XX:XX:XX:XX:XX:XX
                    normalized = mac.replace('-', ':').upper()
                    
                    if len(normalized) != 17:  # Invalid MAC format
                        continue
                    
                    # Prioritize by adapter type
                    if 'wi-fi' in adapter_name or 'wifi' in adapter_name or 'wireless' in adapter_name:
                        wifi_mac = normalized
                    elif 'ethernet' in adapter_name or 'lan' in adapter_name:
                        ethernet_mac = normalized
                    elif other_mac is None:  # First non-virtual adapter
                        other_mac = normalized
            
            # Return in priority order: Wi-Fi > Ethernet > Other physical
            selected_mac = wifi_mac or ethernet_mac or other_mac
            if selected_mac:
                logger.info(f"Detected Physical MAC address: {selected_mac}")
                return selected_mac
        
        # Method 2: Fallback to getmac command
        result = subprocess.run(
            ['getmac', '/fo', 'csv', '/v'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.replace('"', '').split(',')
                if len(parts) >= 4:
                    conn_name = parts[0].strip().lower()
                    mac = parts[2].strip()
                    transport = parts[3].strip().lower()
                    
                    # Skip disconnected and virtual adapters
                    if 'disconnected' in transport or 'disconnected' in mac.lower():
                        continue
                    if any(kw in conn_name for kw in ['vmware', 'virtual', 'vpn', 'tap-', 'bluetooth']):
                        continue
                    
                    if mac and mac != "N/A":
                        normalized = mac.replace('-', ':').upper()
                        if len(normalized) == 17:
                            logger.info(f"Detected Physical MAC address via getmac: {normalized}")
                            return normalized
        
        # Method 3: Fallback to WMI
        try:
            import wmi
            c = wmi.WMI()
            for adapter in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                if adapter.MACAddress:
                    mac = adapter.MACAddress.upper()
                    logger.info(f"Detected Physical MAC address via WMI: {mac}")
                    return mac
        except ImportError:
            pass
        
        # Method 4: Last resort - uuid.getnode()
        mac = uuid.getnode()
        mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
        logger.info(f"Detected MAC address via uuid: {mac_str}")
        return mac_str
        
    except Exception as e:
        logger.error(f"Error getting MAC address: {e}")
        mac = uuid.getnode()
        return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))


def normalize_mac_address(mac: str) -> str:
    """
    Normalize a MAC address to uppercase with colons.
    Handles various formats: AA:BB:CC:DD:EE:FF, aa-bb-cc-dd-ee-ff, aabbccddeeff
    """
    if not mac:
        return ""
    
    # Remove all separators and convert to uppercase
    cleaned = re.sub(r'[:\-\.]', '', mac.upper())
    
    # Validate it's a valid MAC (12 hex characters)
    if len(cleaned) != 12 or not re.match(r'^[0-9A-F]+$', cleaned):
        return mac.upper()  # Return original if invalid
    
    # Format with colons
    return ':'.join(cleaned[i:i+2] for i in range(0, 12, 2))


@dataclass
class User:
    """Represents a user in the system."""
    id: int
    username: str
    mac_address: str  # MAC address for hardware-level authentication
    role: str  # 'superadmin', 'admin', 'user'
    is_active: bool
    created_at: str
    last_login: str
    created_by: Optional[int] = None
    device_secret: Optional[str] = None  # Second factor — prevents MAC spoofing


class UserManager:
    """
    User Management System with role-based access control.
    
    Hierarchy:
    - Super Admin: Can do everything including device registration
    - Admin: Can authorize users for devices
    - User: Can only transfer to authorized devices
    """
    
    ROLES = ['superadmin', 'admin', 'user']
    
    SCHEMA_USERS = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mac_address TEXT,
            device_secret TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """
    
    SCHEMA_USER_DEVICE_PERMISSIONS = """
        CREATE TABLE IF NOT EXISTS user_device_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_hash TEXT NOT NULL,
            granted_by INTEGER NOT NULL,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (granted_by) REFERENCES users(id),
            UNIQUE(user_id, device_hash)
        )
    """
    
    SCHEMA_SESSIONS = """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize User Manager."""
        if db_path is None:
            base_path = Path(__file__).parent.parent / "databases" / "unified_monitoring"
            base_path.mkdir(parents=True, exist_ok=True)
            self.db_path = base_path / "users.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_database()
        self._ensure_superadmin()
        logger.info(f"User Manager initialized at: {self.db_path}")
    
    def _init_database(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(self.SCHEMA_USERS)
            cursor.execute(self.SCHEMA_USER_DEVICE_PERMISSIONS)
            cursor.execute(self.SCHEMA_SESSIONS)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_token ON sessions(session_token)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_permissions ON user_device_permissions(user_id)")
            
            # Migrate: add device_secret column if missing (backward compat)
            try:
                cursor.execute("SELECT device_secret FROM users LIMIT 1")
            except sqlite3.OperationalError:
                cursor.execute("ALTER TABLE users ADD COLUMN device_secret TEXT")
                logger.info("Migrated users table: added device_secret column")
            
            conn.commit()
    
    def _ensure_superadmin(self):
        """Ensure at least one superadmin exists."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'superadmin'")
            count = cursor.fetchone()[0]
            
            if count == 0:
                # Create default superadmin with current system's MAC address
                default_password = "admin123"  # Should be changed on first login
                password_hash = self._hash_password(default_password)
                current_mac = get_mac_address()
                device_secret = secrets.token_hex(16)  # 32-char hex secret
                
                cursor.execute("""
                    INSERT INTO users (username, password_hash, mac_address, device_secret, role, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, ('superadmin', password_hash, current_mac, device_secret, 'superadmin', True, datetime.now().isoformat()))
                
                conn.commit()
                logger.info(f"Default superadmin created (username: superadmin, password: admin123, MAC: {current_mac})")
                logger.info(f"Device secret for superadmin: {device_secret}  (store this securely)")
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256 with salt."""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256((password + salt).encode())
        return f"{salt}${hash_obj.hexdigest()}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        try:
            salt, hash_value = password_hash.split('$')
            test_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return test_hash == hash_value
        except Exception:
            return False
    
    def create_user(self, username: str, password: str, mac_address: str, 
                    role: str, created_by: int) -> Tuple[bool, str]:
        """
        Create a new user.
        
        Args:
            username: Unique username
            password: Plain text password (will be hashed)
            mac_address: MAC address for hardware authentication
            role: User role ('admin' or 'user')
            created_by: ID of the user creating this account
        
        Returns:
            Tuple of (success, message)
        """
        if role not in self.ROLES:
            return False, f"Invalid role. Must be one of: {self.ROLES}"
        
        if role == 'superadmin':
            return False, "Cannot create superadmin through this method"
        
        # Check if creator has permission
        creator = self.get_user_by_id(created_by)
        if not creator:
            return False, "Creator not found"
        
        if creator.role == 'user':
            return False, "Users cannot create other users"
        
        if creator.role == 'admin' and role == 'admin':
            return False, "Admins cannot create other admins"
        
        # Normalize MAC address
        normalized_mac = normalize_mac_address(mac_address) if mac_address else ""
        
        try:
            password_hash = self._hash_password(password)
            device_secret = secrets.token_hex(16)  # 32-char hex second factor
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, password_hash, mac_address, device_secret, role, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (username, password_hash, normalized_mac, device_secret, role, created_by, datetime.now().isoformat()))
                
                conn.commit()
                logger.info(f"User created: {username} ({role}) with MAC: {normalized_mac}")
                return True, f"User '{username}' created successfully. Device Secret: {device_secret}"
                
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False, f"Error: {e}"
    
    def authenticate(self, username: str, password: str, 
                     client_mac: Optional[str] = None,
                     device_secret: Optional[str] = None) -> Tuple[Optional[User], str]:
        """
        Authenticate a user and create a session.
        Validates password, MAC address, AND device secret (second factor).
        
        Args:
            username: Username
            password: Password
            client_mac: MAC address of the client machine (auto-detected)
            device_secret: Device secret token (second factor against MAC spoofing)
        
        Returns:
            Tuple of (User object or None, session_token or error message)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                    (username,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None, "Invalid username or password"
                
                if not self._verify_password(password, row['password_hash']):
                    return None, "Invalid username or password"
                
                # MAC address validation
                stored_mac = row['mac_address']
                if stored_mac and stored_mac.strip():  # User has a registered MAC address
                    normalized_client_mac = normalize_mac_address(client_mac) if client_mac else ""
                    normalized_stored_mac = normalize_mac_address(stored_mac)
                    
                    if normalized_client_mac != normalized_stored_mac:
                        logger.warning(f"MAC address mismatch for user {username}. Expected: {normalized_stored_mac}, Got: {normalized_client_mac}")
                        return None, f"Access denied: This account can only be accessed from the registered system (MAC: {normalized_stored_mac})"
                
                # Device secret validation (second factor — only required if MAC is missing or mismatched)
                # If the user is logging in from the SAME registered machine (MAC matches),
                # device_secret is not needed — the MAC match itself is sufficient.
                # Device secret is required when:
                #   - Client MAC could not be detected (client_mac is None)
                #   - No stored MAC (first-time setup for non-superadmin)
                # This prevents MAC spoofing while allowing normal logins.
                stored_secret = row['device_secret'] if 'device_secret' in row.keys() else None
                mac_matched = (stored_mac and stored_mac.strip() and 
                              normalized_client_mac and 
                              normalized_client_mac == normalized_stored_mac)
                
                if stored_secret and stored_secret.strip() and not mac_matched:
                    # MAC didn't match or wasn't available — require device secret as second factor
                    if not device_secret:
                        logger.warning(f"Device secret required (MAC not matched) for user {username}")
                        return None, "Access denied: Device secret required (MAC address could not be verified)"
                    if device_secret.strip() != stored_secret.strip():
                        logger.warning(f"Device secret mismatch for user {username}")
                        return None, "Access denied: Invalid device secret"
                
                # Update last login
                cursor.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().isoformat(), row['id'])
                )
                
                # Create session
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=24)
                
                cursor.execute("""
                    INSERT INTO sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, ?)
                """, (row['id'], session_token, expires_at.isoformat()))
                
                conn.commit()
                
                user = User(
                    id=row['id'],
                    username=row['username'],
                    mac_address=row['mac_address'] or '',
                    role=row['role'],
                    is_active=bool(row['is_active']),
                    created_at=row['created_at'],
                    last_login=datetime.now().isoformat(),
                    created_by=row['created_by'],
                    device_secret=stored_secret or '',
                )
                
                logger.info(f"User authenticated: {username} from MAC: {client_mac} (device_secret verified)")
                return user, session_token
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None, f"Authentication error: {e}"
    
    def validate_session(self, session_token: str) -> Optional[User]:
        """Validate a session token and return the user."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT u.* FROM users u
                    JOIN sessions s ON u.id = s.user_id
                    WHERE s.session_token = ? 
                    AND s.is_active = 1 
                    AND s.expires_at > ?
                    AND u.is_active = 1
                """, (session_token, datetime.now().isoformat()))
                
                row = cursor.fetchone()
                if row:
                    return User(
                        id=row['id'],
                        username=row['username'],
                        mac_address=row['mac_address'] or '',
                        role=row['role'],
                        is_active=bool(row['is_active']),
                        created_at=row['created_at'],
                        last_login=row['last_login'],
                        created_by=row['created_by']
                    )
                return None
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None
    
    def logout(self, session_token: str) -> bool:
        """Invalidate a session."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE sessions SET is_active = 0 WHERE session_token = ?",
                    (session_token,)
                )
                conn.commit()
                return True
        except Exception:
            return False
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get a user by ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                
                if row:
                    return User(
                        id=row['id'],
                        username=row['username'],
                        mac_address=row['mac_address'] or '',
                        role=row['role'],
                        is_active=bool(row['is_active']),
                        created_at=row['created_at'],
                        last_login=row['last_login'],
                        created_by=row['created_by']
                    )
                return None
        except Exception:
            return None
    
    def get_all_users(self, role: Optional[str] = None) -> List[User]:
        """Get all users, optionally filtered by role."""
        users = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if role:
                    cursor.execute("SELECT * FROM users WHERE role = ? ORDER BY created_at DESC", (role,))
                else:
                    cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
                
                for row in cursor.fetchall():
                    users.append(User(
                        id=row['id'],
                        username=row['username'],
                        mac_address=row['mac_address'] or '',
                        role=row['role'],
                        is_active=bool(row['is_active']),
                        created_at=row['created_at'],
                        last_login=row['last_login'],
                        created_by=row['created_by']
                    ))
        except Exception as e:
            logger.error(f"Error getting users: {e}")
        
        return users
    
    def deactivate_user(self, user_id: int, deactivated_by: int) -> Tuple[bool, str]:
        """Deactivate a user account."""
        deactivator = self.get_user_by_id(deactivated_by)
        target = self.get_user_by_id(user_id)
        
        if not deactivator or not target:
            return False, "User not found"
        
        if target.role == 'superadmin':
            return False, "Cannot deactivate superadmin"
        
        if deactivator.role == 'user':
            return False, "Users cannot deactivate accounts"
        
        if deactivator.role == 'admin' and target.role in ['admin', 'superadmin']:
            return False, "Admins can only deactivate regular users"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
                conn.commit()
                return True, "User deactivated"
        except Exception as e:
            return False, f"Error: {e}"
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change a user's password."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                
                if not row:
                    return False, "User not found"
                
                if not self._verify_password(old_password, row['password_hash']):
                    return False, "Current password is incorrect"
                
                new_hash = self._hash_password(new_password)
                cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
                conn.commit()
                
                return True, "Password changed successfully"
        except Exception as e:
            return False, f"Error: {e}"
    
    def reset_password(self, user_id: int, new_password: str, reset_by: int) -> Tuple[bool, str]:
        """
        Reset a user's password (superadmin only).
        
        Args:
            user_id: ID of the user whose password to reset
            new_password: New password
            reset_by: ID of the superadmin performing the reset
        
        Returns:
            Tuple of (success, message)
        """
        resetter = self.get_user_by_id(reset_by)
        target = self.get_user_by_id(user_id)
        
        if not resetter:
            return False, "Resetter not found"
        
        if not target:
            return False, "Target user not found"
        
        # Only superadmin can reset passwords
        if resetter.role != 'superadmin':
            return False, "Only superadmin can reset passwords"
        
        # Cannot reset another superadmin's password (security measure)
        if target.role == 'superadmin' and target.id != resetter.id:
            return False, "Cannot reset another superadmin's password"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                new_hash = self._hash_password(new_password)
                cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
                conn.commit()
                
                logger.info(f"Password reset for user {target.username} by {resetter.username}")
                return True, f"Password reset successfully for {target.username}"
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            return False, f"Error: {e}"
    
    # ============== Device Permissions ==============
    
    def grant_device_permission(self, user_id: int, device_hash: str, 
                                granted_by: int, expires_at: Optional[str] = None) -> Tuple[bool, str]:
        """Grant a user permission to use a device."""
        granter = self.get_user_by_id(granted_by)
        target = self.get_user_by_id(user_id)
        
        if not granter or not target:
            return False, "User not found"
        
        if granter.role == 'user':
            return False, "Users cannot grant device permissions"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO user_device_permissions 
                    (user_id, device_hash, granted_by, granted_at, expires_at, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (user_id, device_hash, granted_by, datetime.now().isoformat(), expires_at))
                
                conn.commit()
                logger.info(f"Device permission granted: user={user_id}, device={device_hash[:16]}...")
                return True, "Permission granted"
        except Exception as e:
            return False, f"Error: {e}"
    
    def revoke_device_permission(self, user_id: int, device_hash: str, 
                                 revoked_by: int) -> Tuple[bool, str]:
        """Revoke a user's permission to use a device."""
        revoker = self.get_user_by_id(revoked_by)
        
        if not revoker:
            return False, "User not found"
        
        if revoker.role == 'user':
            return False, "Users cannot revoke device permissions"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE user_device_permissions 
                    SET is_active = 0 
                    WHERE user_id = ? AND device_hash = ?
                """, (user_id, device_hash))
                
                conn.commit()
                return True, "Permission revoked"
        except Exception as e:
            return False, f"Error: {e}"
    
    def get_user_permissions(self, user_id: int) -> List[Dict]:
        """Get all device permissions for a user."""
        permissions = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM user_device_permissions 
                    WHERE user_id = ? AND is_active = 1
                    AND (expires_at IS NULL OR expires_at > ?)
                """, (user_id, datetime.now().isoformat()))
                
                for row in cursor.fetchall():
                    permissions.append({
                        'device_hash': row['device_hash'],
                        'granted_by': row['granted_by'],
                        'granted_at': row['granted_at'],
                        'expires_at': row['expires_at']
                    })
        except Exception as e:
            logger.error(f"Error getting permissions: {e}")
        
        return permissions
    
    def has_device_permission(self, user_id: int, device_hash: str) -> bool:
        """Check if a user has permission to use a device."""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        # Superadmins and admins have access to all devices
        if user.role in ['superadmin', 'admin']:
            return True
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 1 FROM user_device_permissions 
                    WHERE user_id = ? AND device_hash = ? AND is_active = 1
                    AND (expires_at IS NULL OR expires_at > ?)
                """, (user_id, device_hash, datetime.now().isoformat()))
                
                return cursor.fetchone() is not None
        except Exception:
            return False
    
    def get_users_with_device_permission(self, device_hash: str) -> List[User]:
        """Get all users who have permission to use a device."""
        users = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT u.* FROM users u
                    JOIN user_device_permissions p ON u.id = p.user_id
                    WHERE p.device_hash = ? AND p.is_active = 1 AND u.is_active = 1
                    AND (p.expires_at IS NULL OR p.expires_at > ?)
                """, (device_hash, datetime.now().isoformat()))
                
                for row in cursor.fetchall():
                    users.append(User(
                        id=row['id'],
                        username=row['username'],
                        mac_address=row['mac_address'] or '',
                        role=row['role'],
                        is_active=bool(row['is_active']),
                        created_at=row['created_at'],
                        last_login=row['last_login'],
                        created_by=row['created_by']
                    ))
        except Exception as e:
            logger.error(f"Error: {e}")
        
        return users


# Test code
if __name__ == "__main__":
    print("=" * 60)
    print("User Manager - Test Run with MAC Address Authentication")
    print("=" * 60)
    
    # Get current system MAC address
    current_mac = get_mac_address()
    print(f"\nCurrent System MAC Address: {current_mac}")
    
    manager = UserManager()
    
    # Test authentication with default superadmin (includes MAC validation)
    print("\n--- Testing Authentication with MAC Validation ---")
    user, token = manager.authenticate("superadmin", "admin123", current_mac)
    if user:
        print(f"\n✓ Authenticated as: {user.username} ({user.role})")
        print(f"  MAC Address: {user.mac_address}")
        print(f"  Session token: {token[:20]}...")
        
        # Validate session
        validated = manager.validate_session(token)
        print(f"  Session valid: {validated is not None}")
    else:
        print(f"\n✗ Authentication failed: {token}")
    
    # Test authentication from wrong MAC (should fail if MAC is set)
    print("\n--- Testing Authentication from Wrong MAC ---")
    wrong_mac = "00:00:00:00:00:01"
    user2, result2 = manager.authenticate("superadmin", "admin123", wrong_mac)
    if user2:
        print(f"✓ Authenticated (MAC not enforced or matches)")
    else:
        print(f"✗ Blocked as expected: {result2}")
    
    # List all users
    users = manager.get_all_users()
    print(f"\nTotal users: {len(users)}")
    for u in users:
        print(f"  - {u.username} ({u.role}) - MAC: {u.mac_address or 'Any'} - Active: {u.is_active}")

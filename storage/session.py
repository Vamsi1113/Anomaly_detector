"""
Session Management
Handles session isolation and data management
"""
import json
import uuid
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import logging
import shutil

from config import SESSION_DIR

logger = logging.getLogger(__name__)


# ============================================================================
# SESSION MODEL
# ============================================================================

class Session:
    """Represents a user session"""
    
    def __init__(self, session_id: str = None):
        """Initialize session"""
        self.session_id = session_id or str(uuid.uuid4())
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.data = {}
        self.session_dir = SESSION_DIR / self.session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)
    
    def set(self, key: str, value: Any) -> None:
        """Set session variable"""
        self.data[key] = value
        self.updated_at = datetime.now()
        self._save()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get session variable"""
        return self.data.get(key, default)
    
    def clear(self) -> None:
        """Clear session data"""
        self.data = {}
        self.updated_at = datetime.now()
        self._save()
    
    def delete(self) -> None:
        """Delete entire session"""
        if self.session_dir.exists():
            shutil.rmtree(self.session_dir)
        logger.info(f"Session {self.session_id} deleted")
    
    def _save(self) -> None:
        """Save session to disk"""
        metadata = {
            'session_id': self.session_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'data': self._serialize_data(self.data),
        }
        
        metadata_file = self.session_dir / 'metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    @staticmethod
    def _serialize_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize data for JSON storage"""
        serialized = {}
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool, type(None))):
                serialized[key] = value
            elif isinstance(value, dict):
                serialized[key] = Session._serialize_data(value)
            elif isinstance(value, list):
                serialized_list = []
                for v in value:
                    if isinstance(v, (str, int, float, bool, type(None))):
                        serialized_list.append(v)
                    elif isinstance(v, dict):
                        serialized_list.append(Session._serialize_data(v))
                    else:
                        # Try to convert to dict if possible, otherwise string
                        if hasattr(v, 'to_dict'):
                            serialized_list.append(v.to_dict())
                        else:
                            serialized_list.append(str(v))
                serialized[key] = serialized_list
            else:
                # Try to convert to dict if possible, otherwise string
                if hasattr(value, 'to_dict'):
                    serialized[key] = value.to_dict()
                else:
                    serialized[key] = str(value)
        return serialized
    
    @classmethod
    def load(cls, session_id: str) -> 'Session':
        """Load session from disk"""
        session = cls(session_id)
        metadata_file = session.session_dir / 'metadata.json'
        
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                session.data = metadata.get('data', {})
                session.created_at = datetime.fromisoformat(metadata.get('created_at'))
                session.updated_at = datetime.fromisoformat(metadata.get('updated_at'))
        
        return session
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        return {
            'session_id': self.session_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'data_keys': list(self.data.keys()),
        }


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    """Manages multiple sessions"""
    
    def __init__(self, session_timeout_hours: int = 1):
        """Initialize session manager"""
        self.session_timeout = timedelta(hours=session_timeout_hours)
        self.sessions = {}
    
    def create_session(self) -> Session:
        """Create new session"""
        session = Session()
        self.sessions[session.session_id] = session
        logger.info(f"Session created: {session.session_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        if session_id in self.sessions:
            return self.sessions[session_id]
        
        # Try to load from disk
        session_dir = SESSION_DIR / session_id
        if session_dir.exists():
            try:
                session = Session.load(session_id)
                self.sessions[session_id] = session
                return session
            except Exception as e:
                logger.error(f"Error loading session {session_id}: {e}")
                return None
        
        return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        if session_id in self.sessions:
            self.sessions[session_id].delete()
            del self.sessions[session_id]
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions"""
        deleted_count = 0
        now = datetime.now()
        
        for session_dir in SESSION_DIR.iterdir():
            if not session_dir.is_dir():
                continue
            
            try:
                metadata_file = session_dir / 'metadata.json'
                if metadata_file.exists():
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        updated_at = datetime.fromisoformat(metadata.get('updated_at'))
                        
                        if now - updated_at > self.session_timeout:
                            shutil.rmtree(session_dir)
                            deleted_count += 1
                            if session_dir.name in self.sessions:
                                del self.sessions[session_dir.name]
            except Exception as e:
                logger.warning(f"Error processing session {session_dir.name}: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} expired sessions")
        
        return deleted_count


# ============================================================================
# GLOBAL SESSION MANAGER
# ============================================================================

_global_session_manager = SessionManager()


def create_session() -> Session:
    """Create new session"""
    return _global_session_manager.create_session()


def get_session(session_id: str) -> Optional[Session]:
    """Get session by ID"""
    return _global_session_manager.get_session(session_id)


def delete_session(session_id: str) -> bool:
    """Delete session"""
    return _global_session_manager.delete_session(session_id)


def cleanup_sessions() -> int:
    """Cleanup expired sessions"""
    return _global_session_manager.cleanup_expired_sessions()

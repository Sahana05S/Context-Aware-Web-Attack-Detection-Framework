"""
Secure log ingestion service.
Handles reading and parsing Nginx JSON logs with OWASP-compliant security practices.
"""
import json
import logging
from pathlib import Path
from typing import Generator, Optional
from app.models import LogEvent
from app.core.config import settings
from pydantic import ValidationError

# Configure logging
logger = logging.getLogger(__name__)

# Resource abuse prevention constants
MAX_LINE_BYTES = 32768  # 32KB max line size
DEFAULT_MAX_EVENTS = 100
HARD_MAX_EVENTS = 200


class LogIngestorError(Exception):
    """Base exception for log ingestion errors"""
    pass


class LogIngestor:
    """
    Secure log file reader and parser.
    
    Security principles implemented:
    1. Read-only file access
    2. No shell command execution
    3. Safe JSON parsing with error handling
    4. Input validation via Pydantic
    5. No dynamic code execution
    6. Graceful error handling (fail-safe)
    7. Path allowlisting (symlink-aware)
    8. Resource caps (line size, event count)
    """
    
    def __init__(self, file_path: Path, allowed_root: Optional[Path] = None):
        """
        Initialize log ingestor with path security checks.
        
        Args:
            file_path: Path to the log file (read-only access)
            allowed_root: Root directory for log files (default: settings.log_root_dir)
        
        Raises:
            LogIngestorError: If file doesn't exist, is not readable, or is outside allowed root
        
        Security:
            - Resolves real path (follows symlinks)
            - Ensures file is inside allowed_root
            - Prevents path traversal and symlink escape attacks
        """
        self.file_path = Path(file_path)
        self.allowed_root = Path(allowed_root) if allowed_root else settings.log_root_dir
        
        # Security: Resolve to absolute real path (follows symlinks)
        try:
            # Get the current working directory as base
            cwd = Path.cwd()
            
            # Resolve allowed_root to absolute path
            if not self.allowed_root.is_absolute():
                allowed_root_resolved = (cwd / self.allowed_root).resolve()
            else:
                allowed_root_resolved = self.allowed_root.resolve()
            
            # Resolve file_path to absolute real path
            if not self.file_path.is_absolute():
                file_path_resolved = (cwd / self.file_path).resolve(strict=True)
            else:
                file_path_resolved = self.file_path.resolve(strict=True)
            
            # Security: Ensure file is inside allowed root (prevents symlink escape)
            try:
                file_path_resolved.relative_to(allowed_root_resolved)
            except ValueError:
                raise LogIngestorError(
                    f"Access denied: File path {file_path_resolved} is outside allowed root {allowed_root_resolved}"
                )
            
            # Update to resolved paths
            self.file_path = file_path_resolved
            self.allowed_root = allowed_root_resolved
            
        except FileNotFoundError:
            raise LogIngestorError(f"Log file does not exist: {self.file_path}")
        except RuntimeError as e:
            raise LogIngestorError(f"Failed to resolve path (possible symlink loop): {e}")
        
        # Security: Validate file exists and is a regular file
        if not self.file_path.is_file():
            raise LogIngestorError(f"Path is not a file: {self.file_path}")
        
        # Security: Check read permissions
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                pass
        except PermissionError:
            raise LogIngestorError(f"No read permission for file: {self.file_path}")
        except Exception as e:
            raise LogIngestorError(f"Cannot access file {self.file_path}: {e}")
    
    def read_logs(self, max_events: int = DEFAULT_MAX_EVENTS) -> Generator[LogEvent, None, None]:
        """
        Read and parse log file line by line.
        
        Args:
            max_events: Maximum number of events to return (capped at HARD_MAX_EVENTS)
        
        Security:
        - Read-only mode ('r')
        - UTF-8 encoding specified
        - No shell command execution
        - Generator pattern for memory efficiency
        - Line size cap (MAX_LINE_BYTES)
        - Event count cap (max_events)
        
        Yields:
            LogEvent: Parsed and validated log events
        """
        # Security: Cap max_events at HARD_MAX_EVENTS
        max_events = min(max_events, HARD_MAX_EVENTS)
        
        logger.info(f"Starting log ingestion from: {self.file_path} (max events: {max_events})")
        
        try:
            # Security: Open in read-only mode with explicit encoding
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as file:
                line_number = 0
                events_yielded = 0
                
                for line in file:
                    line_number += 1
                    
                    # Security: Skip lines that are too long (DoS prevention)
                    if len(line) > MAX_LINE_BYTES:
                        logger.warning(
                            f"Skipping oversized line {line_number}: {len(line)} bytes (max: {MAX_LINE_BYTES})"
                        )
                        continue
                    
                    line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Parse and validate the line
                    log_event = self.parse_log_line(line, line_number)
                    
                    if log_event:
                        yield log_event
                        events_yielded += 1
                        
                        # Security: Cap total events yielded
                        if events_yielded >= max_events:
                            logger.info(f"Reached max events limit ({max_events}), stopping ingestion")
                            break
        
        except IOError as e:
            logger.error(f"IO error reading log file: {e}")
            raise LogIngestorError(f"Failed to read log file: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during log ingestion: {e}")
            raise LogIngestorError(f"Unexpected error: {e}")
    
    def parse_log_line(self, line: str, line_number: int = 0) -> Optional[LogEvent]:
        """
        Parse a single JSON log line into a LogEvent.
        
        Security:
        - Safe JSON parsing (no eval or exec)
        - Pydantic validation for all fields
        - Error handling prevents crashes
        - Malformed data is logged and skipped
        - Line size check
        
        Args:
            line: JSON string to parse
            line_number: Line number for error reporting
        
        Returns:
            LogEvent if parsing succeeds, None if it fails
        """
        # Security: Additional line size check
        if len(line) > MAX_LINE_BYTES:
            logger.warning(f"Line {line_number} exceeds max size ({len(line)} > {MAX_LINE_BYTES})")
            return None
        
        try:
            # Security: Use json.loads (safe) - never eval()
            data = json.loads(line)
            
            # Validate and normalize using Pydantic
            log_event = LogEvent(**data)
            
            return log_event
        
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON at line {line_number}: {e}")
            logger.debug(f"Malformed line content: {line[:100]}...")
            return None
        
        except ValidationError as e:
            logger.warning(f"Validation failed at line {line_number}: {e}")
            logger.debug(f"Invalid data: {line[:100]}...")
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error parsing line {line_number}: {e}")
            return None
    
    def tail_logs(self, follow: bool = False, max_events: int = DEFAULT_MAX_EVENTS) -> Generator[LogEvent, None, None]:
        """
        Tail log file (read from beginning, optionally follow new entries).
        
        For POC: This reads the entire file. 
        Production: Would implement proper tailing with inotify/watchdog.
        
        Args:
            follow: If True, keep watching for new entries (not yet implemented)
            max_events: Maximum number of events to return
        
        Yields:
            LogEvent: Parsed log events
        """
        if follow:
            logger.warning("Follow mode not yet implemented - reading file once")
        
        yield from self.read_logs(max_events=max_events)


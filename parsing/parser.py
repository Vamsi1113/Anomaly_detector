"""
Log and CSV File Parsing Module
Universal parser that handles ANY CSV file format
"""
import re
import csv
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class GenericRecord:
    """Represents a single row from any CSV file"""
    row_index: int
    data: Dict[str, Any]
    identifier: str = ""  # Best guess at unique identifier
    timestamp: str = ""   # Best guess at timestamp
    
    def __post_init__(self):
        """Auto-detect identifier and timestamp after initialization"""
        if not self.identifier:
            self.identifier = self._find_identifier()
        if not self.timestamp:
            self.timestamp = self._find_timestamp()
    
    def _find_identifier(self) -> str:
        """Find the best column to use as identifier"""
        # Priority: id, ip, email, user, name, or first column
        priority_keys = ['id', 'ip', 'client_ip', 'email', 'user', 'username', 'name']
        
        for key in priority_keys:
            for col_name, value in self.data.items():
                if key in col_name.lower():
                    return str(value)
        
        # Fallback: use first column value
        if self.data:
            return str(list(self.data.values())[0])
        
        return f"row_{self.row_index}"
    
    def _find_timestamp(self) -> str:
        """Find the best column to use as timestamp"""
        # Priority: timestamp, time, date, created
        priority_keys = ['timestamp', 'time', 'date', 'created', 'datetime']
        
        for key in priority_keys:
            for col_name, value in self.data.items():
                if key in col_name.lower():
                    return str(value)
        
        return ""


@dataclass
class HTTPRecord:
    """Represents a single HTTP log entry (legacy support)"""
    timestamp: str
    client_ip: str
    method: str
    uri: str
    status_code: int
    response_size: int
    duration: int
    user_agent: str
    raw_row: Dict[str, Any]


# ============================================================================
# UNIVERSAL CSV PARSER
# ============================================================================

class UniversalCSVParser:
    """Parse ANY CSV file format"""
    
    def parse(self, filepath: Path) -> Tuple[List[GenericRecord], List[str], Dict[str, Any]]:
        """
        Parse any CSV file
        
        Returns:
            Tuple of (records, error_messages, schema_info)
        """
        records = []
        errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Auto-detect dialect
                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = 'excel'
                
                f.seek(0)
                reader = csv.DictReader(f, dialect=dialect)
                
                # Validate headers
                if not reader.fieldnames:
                    raise ValueError("CSV file has no headers")
                
                columns = list(reader.fieldnames)
                logger.info(f"Detected {len(columns)} columns: {columns}")
                
                # Parse all rows
                for row_idx, row in enumerate(reader):
                    try:
                        record = GenericRecord(
                            row_index=row_idx,
                            data=dict(row)
                        )
                        records.append(record)
                    except Exception as e:
                        errors.append(f"Line {row_idx + 2}: {str(e)}")
                        continue
                
                # Analyze schema
                schema_info = self._analyze_schema(columns, records)
                
                logger.info(f"Parsed {len(records)} records from {filepath.name}")
                if errors:
                    logger.warning(f"Encountered {len(errors)} parsing errors")
                
                return records, errors, schema_info
        
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {str(e)}")
            raise
    
    def _analyze_schema(self, columns: List[str], records: List[GenericRecord]) -> Dict[str, Any]:
        """Analyze the CSV schema to understand data types"""
        if not records:
            return {'columns': columns, 'types': {}, 'numeric_columns': [], 'categorical_columns': []}
        
        # Sample first few records to detect types
        sample_size = min(100, len(records))
        sample_records = records[:sample_size]
        
        column_types = {}
        numeric_columns = []
        categorical_columns = []
        
        for col in columns:
            # Collect sample values
            values = [r.data.get(col) for r in sample_records if r.data.get(col) not in [None, '', 'None']]
            
            if not values:
                column_types[col] = 'empty'
                continue
            
            # Try to detect type
            numeric_count = 0
            for val in values:
                try:
                    float(str(val))
                    numeric_count += 1
                except (ValueError, TypeError):
                    pass
            
            # If >80% numeric, treat as numeric
            if numeric_count / len(values) > 0.8:
                column_types[col] = 'numeric'
                numeric_columns.append(col)
            else:
                column_types[col] = 'categorical'
                categorical_columns.append(col)
        
        return {
            'columns': columns,
            'types': column_types,
            'numeric_columns': numeric_columns,
            'categorical_columns': categorical_columns,
            'total_columns': len(columns),
            'total_records': len(records)
        }


# ============================================================================
# SYSLOG PARSER
# ============================================================================

class SyslogParser:
    """Parse raw syslog format entries"""
    
    def parse(self, filepath: Path) -> Tuple[List[HTTPRecord], List[str]]:
        """Parse syslog format file with flexible pattern matching"""
        records = []
        errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split by syslog entry start pattern (any priority number, not just 150)
            log_entries = re.split(r'(?=<\d+>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)', content)
            
            total_entries = len([e for e in log_entries if e.strip()])
            logger.info(f"Found {total_entries} log entries to parse")
            
            for line_num, log_line in enumerate(log_entries, 1):
                if not log_line.strip():
                    continue
                
                log_line = log_line.strip()
                
                try:
                    # Pattern 1: Full format with port and domain
                    # <150>Jan 28 08:59:59 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1 12345 abc.example.net - - [timestamp] "GET /uri HTTP/1.1" 200 size duration "ref" "ua"
                    pattern1 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'(?P<port>\d+)\s+(?P<domain>\S+)\s+'
                        r'[^\[]*\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)\s+(?P<duration>[\d\-]+)'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 2: Format without port (has - - instead)
                    # <150>Jan 28 08:59:59 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1 - - [timestamp] "POST /uri HTTP/1.1" 200 size duration
                    pattern2 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                        r'(?:\s+\d+)?'
                    )
                    
                    # Pattern 3: Format with port number instead of dash
                    # <150>Jan 28 09:00:01 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1 - 365560 - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern3 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+(?P<dest_ip>[\d\.]+)\s+'
                        r'-\s+(?P<port>\d+)\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 4: Different hostname format
                    # <150>Jan 28 14:09:16 INMUPA0100LSG12 httpd[2338514]: 172.17.249.64 - - localhost - - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern4 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+-\s+-\s+(?P<domain>\S+)\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 5: Minimal format (IP - - - [timestamp])
                    # <150>Jan 28 12:31:48 inmura0364lw01 httpd[320519]: 10.61.194.7 - - - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern5 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+-\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 6: Minimal format with 4 dashes (IP - - - - [timestamp])
                    # <150>Jan 28 12:31:48 inmura0364lw01 httpd[320542]: 10.61.194.7 - - - - [timestamp] "GET /uri HTTP/1.1" 200 size duration
                    pattern6 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+-\s+-\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Pattern 7: Format with comma in IP field (IP1, IP2 - - [timestamp])
                    # <150>Jan 28 08:10:00 servernameabc httpd[12345]: 0.0.0.0 0.1.0.1, 10.52.156.33 - - [timestamp] "GET / HTTP/1.1" 200 size duration
                    pattern7 = re.compile(
                        r'<\d+>(?P<syslog_timestamp>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+'
                        r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+'
                        r'(?P<source_ip>[\d\.]+)\s+[\d\.]+,\s+[\d\.]+\s+-\s+-\s+'
                        r'\[(?P<timestamp>[^\]]+)\]\s+'
                        r'"+(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/[\d\.]+"+\s+'
                        r'(?P<status_code>\d+)\s+(?P<response_size>[\d\-]+)(?:\s+(?P<duration>[\d\-]+))?'
                        r'(?:\s+\d+)?'
                        r'(?:\s+"+(?P<referer>[^"]*?)"+)?'
                        r'(?:\s+"+(?P<user_agent>[^"]*?)"+)?'
                    )
                    
                    # Try all patterns
                    match = None
                    for pattern in [pattern1, pattern2, pattern3, pattern4, pattern5, pattern6, pattern7]:
                        match = pattern.search(log_line)
                        if match:
                            break
                    
                    if not match:
                        if '<' in log_line and 'HTTP' in log_line:
                            errors.append(f"Line {line_num}: Could not parse - {log_line[:150]}")
                        continue
                    
                    groups = match.groupdict()
                    
                    # Handle missing or dash values
                    response_size = groups.get('response_size', '0')
                    if response_size == '-' or not response_size:
                        response_size = '0'
                    
                    duration = groups.get('duration', '0')
                    if duration == '-' or not duration or duration is None:
                        duration = '0'
                    
                    port = groups.get('port', '0')
                    if not port or port == '-':
                        port = '0'
                    
                    dest_ip = groups.get('dest_ip', '0.0.0.0')
                    if not dest_ip or dest_ip == '-':
                        dest_ip = '0.0.0.0'
                    
                    # Clean fields - remove extra quotes
                    uri = groups.get('uri', '').strip('"').strip()
                    user_agent = (groups.get('user_agent') or '').strip('"').strip()
                    referer = (groups.get('referer') or '').strip('"').strip()
                    domain = groups.get('domain', '')
                    
                    record = HTTPRecord(
                        timestamp=groups.get('timestamp', ''),
                        client_ip=groups.get('source_ip', ''),
                        method=groups.get('method', '').upper(),
                        uri=uri,
                        status_code=int(groups.get('status_code', 0)),
                        response_size=int(response_size),
                        duration=int(duration),
                        user_agent=user_agent,
                        raw_row={
                            'hostname': groups.get('hostname', ''),
                            'process': groups.get('process', ''),
                            'dest_ip': dest_ip,
                            'port': port,
                            'domain': domain,
                            'referer': referer,
                        }
                    )
                    records.append(record)
                
                except (ValueError, KeyError, TypeError) as e:
                    errors.append(f"Line {line_num}: {str(e)}")
                    continue
            
            logger.info(f"Parsed {len(records)} syslog records from {filepath.name} (expected {total_entries})")
            if errors:
                logger.warning(f"Encountered {len(errors)} parsing errors")
                for error in errors[:5]:
                    logger.warning(error)
            
            return records, errors
        
        except Exception as e:
            logger.error(f"Error reading syslog file {filepath}: {str(e)}")
            raise


# ============================================================================
# HTTP LOG PARSER (Legacy Support)
# ============================================================================

class HTTPLogParser:
    """Parse HTTP log format (legacy support)"""
    
    REQUIRED_FIELDS = {'timestamp', 'client_ip', 'method', 'uri', 
                      'status_code', 'response_size', 'duration', 'user_agent'}
    
    def parse(self, filepath: Path) -> Tuple[List[HTTPRecord], List[str]]:
        """Parse HTTP log CSV file"""
        records = []
        errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = 'excel'
                
                f.seek(0)
                reader = csv.DictReader(f, dialect=dialect)
                
                if not reader.fieldnames:
                    raise ValueError("CSV file has no headers")
                
                actual_fields = set(reader.fieldnames)
                
                if not self.REQUIRED_FIELDS.issubset(actual_fields):
                    missing = self.REQUIRED_FIELDS - actual_fields
                    raise ValueError(f"Missing required fields: {missing}")
                
                for line_num, row in enumerate(reader, 2):
                    try:
                        record = HTTPRecord(
                            timestamp=str(row['timestamp']).strip(),
                            client_ip=str(row['client_ip']).strip(),
                            method=str(row['method']).strip().upper(),
                            uri=str(row['uri']).strip(),
                            status_code=int(row['status_code']),
                            response_size=int(row['response_size']),
                            duration=int(row['duration']),
                            user_agent=str(row['user_agent']).strip(),
                            raw_row=row
                        )
                        records.append(record)
                    except (ValueError, KeyError, TypeError) as e:
                        errors.append(f"Line {line_num}: {str(e)}")
                        continue
            
            logger.info(f"Parsed {len(records)} HTTP records from {filepath.name}")
            if errors:
                logger.warning(f"Encountered {len(errors)} parsing errors")
            
            return records, errors
        
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {str(e)}")
            raise


# ============================================================================
# UNIVERSAL PARSER
# ============================================================================

class UniversalParser:
    """Main parser that handles ANY CSV file"""
    
    def __init__(self):
        self.universal_parser = UniversalCSVParser()
        self.http_parser = HTTPLogParser()
        self.syslog_parser = SyslogParser()
    
    def parse(self, filepath: Path) -> Tuple[List[Any], List[str], str, Optional[Dict[str, Any]]]:
        """
        Parse file - tries syslog, then HTTP format, then falls back to universal
        
        Returns:
            Tuple of (records, errors, file_type, schema_info)
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        suffix = filepath.suffix.lower()
        
        if suffix not in ['.log', '.txt', '.csv']:
            raise ValueError(f"Unsupported file type: {suffix}")
        
        # Try syslog format first (for raw log files)
        try:
            records, errors = self.syslog_parser.parse(filepath)
            if records:  # Only accept if we got some records
                logger.info(f"Parsed as syslog format")
                return records, errors, 'http', None
        except Exception as e:
            logger.debug(f"Not syslog format: {e}")
        
        # Try HTTP format (for structured CSV with HTTP columns)
        try:
            records, errors = self.http_parser.parse(filepath)
            logger.info(f"Parsed as HTTP log format")
            return records, errors, 'http', None
        except ValueError as e:
            # Not HTTP format, use universal parser
            logger.info(f"Not HTTP format ({e}), using universal parser")
            records, errors, schema_info = self.universal_parser.parse(filepath)
            return records, errors, 'generic', schema_info
        
        if not records:
            raise ValueError("No valid records could be parsed from file")


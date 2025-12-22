import os
import re
import hashlib
import magic
from datetime import datetime

def scan_system(directory="/", file_types=None, deep_scan=False):
    """
    Enhanced system scanner with multiple detection methods
    
    Args:
        directory: Directory to scan
        file_types: List of file extensions to check
        deep_scan: Perform deep content analysis
    
    Returns:
        Dictionary with suspicious files and their details
    """
    if file_types is None:
        file_types = ['.exe', '.bat', '.sh', '.py', '.js', '.php', '.jar', '.vbs']
    
    suspicious_files = []
    potential_threats = []
    
    # Known malicious file patterns
    malware_patterns = [
        r"eval\s*\(.*base64_decode",
        r"system\s*\(.*\$_GET",
        r"shell_exec\s*\(.*\)",
        r"wget.*http://",
        r"curl.*http://",
        r"powershell.*-EncodedCommand",
        r"Invoke-Expression",
        r"from.*import.*socket.*threading",
        r"import.*os.*subprocess",
        r"exec\s*\(.*\)",
    ]
    
    # Known suspicious strings
    suspicious_strings = [
        "c99shell", "r57shell", "b374k", "web shell",
        "cryptominer", "xmrig", "minerd", "mining",
        "keylogger", "rat", "backdoor", "trojan",
        "meterpreter", "metasploit", "payload",
        "reverse_shell", "bind_shell",
    ]
    
    for root, dirs, files in os.walk(directory):
        # Skip system directories to save time
        skip_dirs = ['/proc', '/sys', '/dev', '/run']
        if any(root.startswith(sd) for sd in skip_dirs):
            continue
        
        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                # Check 1: File extension
                ext_matches = any(file.endswith(ext) for ext in file_types)
                
                # Check 2: File permissions (world-writable)
                stat = os.stat(filepath)
                if stat.st_mode & 0o002:  # World-writable
                    suspicious = True
                    reason = "World-writable file"
                else:
                    suspicious = ext_matches
                    reason = "Suspicious extension" if ext_matches else None
                
                # Check 3: Hidden files (starting with .)
                if file.startswith('.'):
                    suspicious = True
                    reason = "Hidden file"
                
                # Check 4: Large binary files in unusual locations
                if file.endswith(('.exe', '.dll', '.so')) and 'home' in root.lower():
                    suspicious = True
                    reason = "Binary in home directory"
                
                # Deep content analysis if enabled
                if deep_scan and suspicious:
                    content_analysis = analyze_file_content(filepath, malware_patterns, suspicious_strings)
                    if content_analysis['suspicious']:
                        reason = content_analysis['reason']
                
                if suspicious:
                    file_info = {
                        'path': filepath,
                        'filename': file,
                        'size': stat.st_size,
                        'permissions': oct(stat.st_mode)[-3:],
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'reason': reason,
                        'suspicious_score': calculate_suspicion_score(filepath, reason)
                    }
                    
                    # Add content analysis results if available
                    if deep_scan and 'content_analysis' in locals():
                        file_info['content_matches'] = content_analysis.get('matches', [])
                    
                    suspicious_files.append(file_info)
                    
                    # Check for potential threats
                    if file_info['suspicious_score'] > 70:
                        potential_threats.append(file_info)
                        
            except (PermissionError, FileNotFoundError, OSError):
                continue  # Skip files we can't access
    
    return {
        'suspicious_files': suspicious_files,
        'potential_threats': potential_threats,
        'total_scanned': len(suspicious_files),
        'high_risk_count': len(potential_threats),
        'scan_time': datetime.now().isoformat(),
        'directory': directory
    }

def analyze_file_content(filepath, malware_patterns, suspicious_strings):
    """Analyze file content for malicious patterns"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(10000)  # Read first 10KB
        
        matches = []
        
        # Check for malware patterns
        for pattern in malware_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(f"Malware pattern: {pattern}")
        
        # Check for suspicious strings
        for string in suspicious_strings:
            if string.lower() in content.lower():
                matches.append(f"Suspicious string: {string}")
        
        # Check for encoded data
        if 'base64' in content.lower() and len(content) > 1000:
            matches.append("Possible base64 encoded payload")
        
        # Check for long lines (common in obfuscated code)
        lines = content.split('\n')
        long_lines = [line for line in lines if len(line) > 500]
        if long_lines:
            matches.append(f"Contains {len(long_lines)} very long lines (>500 chars)")
        
        return {
            'suspicious': len(matches) > 0,
            'matches': matches,
            'reason': ', '.join(matches[:3]) if matches else None
        }
        
    except Exception:
        return {'suspicious': False, 'matches': [], 'reason': None}

def calculate_suspicion_score(filepath, reason):
    """Calculate a suspicion score from 0-100"""
    score = 0
    
    # Base score based on reason
    if reason:
        if "World-writable" in reason:
            score += 30
        if "Hidden" in reason:
            score += 20
        if "Binary" in reason:
            score += 25
        if "Suspicious extension" in reason:
            score += 15
        if "Malware pattern" in reason:
            score += 50
        if "Suspicious string" in reason:
            score += 40
    
    # Additional checks
    try:
        # Check file size (very small or very large)
        size = os.path.getsize(filepath)
        if size < 100 or size > 10000000:  # <100B or >10MB
            score += 10
        
        # Check if file is in /tmp
        if '/tmp/' in filepath:
            score += 15
            
        # Check if file is in /var/www (web directory)
        if '/var/www/' in filepath:
            score += 20
            
    except:
        pass
    
    return min(score, 100)  # Cap at 100

def get_file_type(filepath):
    """Get file type using magic numbers"""
    try:
        import magic
        mime = magic.Magic(mime=True)
        return mime.from_file(filepath)
    except:
        try:
            import subprocess
            result = subprocess.run(['file', '--mime-type', '-b', filepath], 
                                  capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "unknown"

# Quick scan function
def quick_scan(directory="/home"):
    """Quick scan for common suspicious files"""
    return scan_system(directory, 
                      file_types=['.exe', '.bat', '.sh', '.py', '.php', '.js'],
                      deep_scan=False)

# Deep scan function  
def deep_scan(directory="/"):
    """Deep scan with content analysis"""
    return scan_system(directory, 
                      file_types=['.exe', '.bat', '.sh', '.py', '.php', '.js', '.jar', '.vbs', '.pl'],
                      deep_scan=True)

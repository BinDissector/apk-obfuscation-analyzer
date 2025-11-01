#!/usr/bin/env python3
"""
APK/AAR Obfuscation Analyzer
Compares Android APKs/AARs before and after obfuscation to measure effectiveness
"""

import os
import re
import json
import shutil
import argparse
import subprocess
import tempfile
import zipfile
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import base64
import math
import hashlib


class APKAnalyzer:
    """Main analyzer class for APK obfuscation analysis"""

    def __init__(self, jadx_path="jadx", verbose=False, jadx_timeout=900, jadx_memory="4G"):
        """
        Initialize the analyzer

        Args:
            jadx_path: Path to jadx executable
            verbose: Enable verbose output
            jadx_timeout: Timeout in seconds for jadx decompilation (default: 900 = 15 minutes)
            jadx_memory: Maximum JVM memory for jadx (default: 4G)
        """
        self.jadx_path = jadx_path
        self.verbose = verbose
        self.jadx_timeout = jadx_timeout
        self.jadx_memory = jadx_memory
        self.dictionary_words = self._load_dictionary()

    def _load_dictionary(self):
        """Load common English words for meaningful name detection"""
        # Common programming terms and dictionary words
        words = set([
            'activity', 'fragment', 'adapter', 'manager', 'service', 'receiver',
            'provider', 'helper', 'utils', 'util', 'handler', 'listener',
            'builder', 'factory', 'singleton', 'model', 'view', 'controller',
            'repository', 'database', 'network', 'api', 'client', 'server',
            'request', 'response', 'config', 'settings', 'preferences',
            'user', 'account', 'login', 'auth', 'token', 'session',
            'button', 'text', 'image', 'layout', 'dialog', 'menu',
            'main', 'home', 'profile', 'detail', 'list', 'item',
            'data', 'info', 'message', 'error', 'result', 'status',
            'create', 'update', 'delete', 'read', 'write', 'save',
            'load', 'init', 'start', 'stop', 'pause', 'resume',
            'show', 'hide', 'open', 'close', 'connect', 'disconnect'
        ])
        return words

    def log(self, message):
        """Print message if verbose mode enabled"""
        if self.verbose:
            print(f"[DEBUG] {message}")

    def _check_disk_space(self, path, required_gb=5):
        """
        Check if sufficient disk space is available

        Args:
            path: Path to check disk space for
            required_gb: Required free space in GB (default: 5)

        Returns:
            bool: True if sufficient space, False otherwise
        """
        try:
            stat = os.statvfs(path)
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            self.log(f"Available disk space: {free_gb:.2f} GB")

            if free_gb < required_gb:
                print(f"⚠ WARNING: Low disk space ({free_gb:.1f} GB available, {required_gb} GB recommended)")
                print(f"  Decompilation may fail if disk space runs out.")
                return False
            return True
        except Exception as e:
            self.log(f"Could not check disk space: {e}")
            return True  # Don't block if we can't check

    def _calculate_file_hashes(self, file_path):
        """
        Calculate multiple hash values for a file

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with hash values (md5, sha1, sha256)
        """
        self.log(f"Calculating hashes for {file_path}")

        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)

            result = {
                'md5': hashes['md5'].hexdigest(),
                'sha1': hashes['sha1'].hexdigest(),
                'sha256': hashes['sha256'].hexdigest()
            }

            self.log(f"SHA256: {result['sha256']}")
            return result

        except Exception as e:
            self.log(f"Error calculating hashes: {e}")
            return {
                'md5': 'N/A',
                'sha1': 'N/A',
                'sha256': 'N/A',
                'error': str(e)
            }

    def _extract_signature_info(self, apk_path):
        """
        Extract signature/certificate information from APK

        Args:
            apk_path: Path to APK file

        Returns:
            Dictionary with signature information
        """
        self.log(f"Extracting signature info from {apk_path}")

        signature_info = {
            'signed': False,
            'certificates': [],
            'v1_signed': False,
            'v2_signed': False,
            'v3_signed': False,
        }

        try:
            # Check if it's an APK (AARs don't have signatures)
            if not apk_path.lower().endswith('.apk'):
                signature_info['note'] = 'Not an APK file - signature info not applicable'
                return signature_info

            # Extract certificate files from META-INF
            with zipfile.ZipFile(apk_path, 'r') as zf:
                meta_inf_files = [name for name in zf.namelist() if name.startswith('META-INF/')]

                # Check for v1 signature (JAR signing)
                cert_files = [f for f in meta_inf_files if f.endswith(('.RSA', '.DSA', '.EC'))]
                if cert_files:
                    signature_info['v1_signed'] = True
                    signature_info['signed'] = True

                # Try to read certificate details using keytool
                for cert_file in cert_files[:1]:  # Process first certificate
                    try:
                        # Extract certificate to temp file
                        with tempfile.NamedTemporaryFile(suffix='.rsa', delete=False) as temp_cert:
                            temp_cert.write(zf.read(cert_file))
                            temp_cert_path = temp_cert.name

                        # Use keytool to read certificate
                        result = subprocess.run(
                            ['keytool', '-printcert', '-file', temp_cert_path],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )

                        if result.returncode == 0:
                            cert_info = self._parse_keytool_output(result.stdout)
                            signature_info['certificates'].append(cert_info)

                        # Clean up temp file
                        os.unlink(temp_cert_path)

                    except Exception as e:
                        self.log(f"Could not read certificate {cert_file}: {e}")

            # Try apksigner to get v2/v3 signature scheme info
            try:
                result = subprocess.run(
                    ['apksigner', 'verify', '--verbose', apk_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    output = result.stdout
                    if 'v2 scheme' in output.lower() or 'v2 signature' in output.lower():
                        signature_info['v2_signed'] = True
                        signature_info['signed'] = True
                    if 'v3 scheme' in output.lower() or 'v3 signature' in output.lower():
                        signature_info['v3_signed'] = True
                        signature_info['signed'] = True

            except FileNotFoundError:
                self.log("apksigner not found - v2/v3 signature detection unavailable")
            except Exception as e:
                self.log(f"apksigner check failed: {e}")

        except zipfile.BadZipFile:
            signature_info['error'] = 'Invalid APK file'
        except Exception as e:
            signature_info['error'] = str(e)
            self.log(f"Error extracting signature info: {e}")

        return signature_info

    def _parse_keytool_output(self, keytool_output):
        """
        Parse keytool output to extract certificate information

        Args:
            keytool_output: Output from keytool -printcert

        Returns:
            Dictionary with certificate details
        """
        cert_info = {}

        try:
            # Extract common fields
            patterns = {
                'owner': r'Owner:\s*(.+)',
                'issuer': r'Issuer:\s*(.+)',
                'serial': r'Serial number:\s*(.+)',
                'valid_from': r'Valid from:\s*(.+?)\s*until',
                'valid_until': r'until:\s*(.+)',
                'fingerprint_sha256': r'SHA256:\s*(.+)',
                'fingerprint_sha1': r'SHA1:\s*(.+)',
                'signature_algorithm': r'Signature algorithm name:\s*(.+)',
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, keytool_output, re.IGNORECASE)
                if match:
                    cert_info[key] = match.group(1).strip()

            # Extract CN (Common Name) from Owner
            if 'owner' in cert_info:
                cn_match = re.search(r'CN=([^,]+)', cert_info['owner'])
                if cn_match:
                    cert_info['common_name'] = cn_match.group(1)

        except Exception as e:
            self.log(f"Error parsing keytool output: {e}")

        return cert_info

    def check_jadx_available(self):
        """Verify jadx is installed and accessible"""
        try:
            result = subprocess.run(
                [self.jadx_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            self.log(f"jadx version: {result.stdout.strip()}")
            return True
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"ERROR: jadx not found at '{self.jadx_path}'")
            print("Please install jadx: https://github.com/skylot/jadx")
            print("Or specify the correct path with --jadx-path")
            return False

    def _detect_file_type(self, file_path):
        """
        Detect if file is APK or AAR

        Args:
            file_path: Path to file

        Returns:
            'apk', 'aar', or None if unknown
        """
        if file_path.lower().endswith('.apk'):
            return 'apk'
        elif file_path.lower().endswith('.aar'):
            return 'aar'
        else:
            # Try to detect by contents
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    namelist = zf.namelist()
                    # AAR contains classes.jar
                    if 'classes.jar' in namelist:
                        return 'aar'
                    # APK contains classes.dex
                    elif any(name.startswith('classes') and name.endswith('.dex') for name in namelist):
                        return 'apk'
            except:
                pass
        return None

    def _extract_jar_from_aar(self, aar_path, output_dir):
        """
        Extract classes.jar from AAR file

        Args:
            aar_path: Path to AAR file
            output_dir: Directory to extract JAR

        Returns:
            Path to extracted JAR file
        """
        self.log(f"Extracting classes.jar from AAR: {aar_path}")

        try:
            with zipfile.ZipFile(aar_path, 'r') as zf:
                # Check if classes.jar exists
                if 'classes.jar' not in zf.namelist():
                    raise RuntimeError(f"AAR file does not contain classes.jar: {aar_path}")

                # Extract classes.jar
                jar_path = os.path.join(output_dir, 'classes.jar')
                with open(jar_path, 'wb') as jar_file:
                    jar_file.write(zf.read('classes.jar'))

                self.log(f"Extracted JAR to: {jar_path}")
                return jar_path

        except zipfile.BadZipFile:
            raise RuntimeError(f"Invalid AAR file (not a valid ZIP): {aar_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to extract JAR from AAR: {e}")

    def decompile_apk(self, apk_path, output_dir, max_retries=2):
        """
        Decompile APK or AAR using jadx with robustness improvements

        Args:
            apk_path: Path to APK or AAR file
            output_dir: Directory for decompiled output
            max_retries: Maximum number of retry attempts (default: 2)

        Returns:
            Path to decompiled sources directory
        """
        self.log(f"Decompiling {apk_path}...")

        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"File not found: {apk_path}")

        # Check file size and provide estimate
        file_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        self.log(f"File size: {file_size_mb:.2f} MB")

        if file_size_mb > 100:
            estimated_time = int(file_size_mb / 10)  # Rough estimate: 10MB per minute
            print(f"Large file detected ({file_size_mb:.1f} MB). Decompilation may take {estimated_time}+ minutes...")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Check available disk space (estimate 5x file size needed for decompilation)
        required_space_gb = max(5, (file_size_mb * 5) / 1024)
        self._check_disk_space(output_dir, required_space_gb)

        # Detect file type
        file_type = self._detect_file_type(apk_path)
        if file_type is None:
            raise RuntimeError(f"Unknown file type (expected APK or AAR): {apk_path}")

        self.log(f"Detected file type: {file_type.upper()}")

        # If AAR, extract classes.jar first
        target_file = apk_path
        if file_type == 'aar':
            temp_jar_dir = os.path.join(output_dir, '_temp_jar')
            os.makedirs(temp_jar_dir, exist_ok=True)
            target_file = self._extract_jar_from_aar(apk_path, temp_jar_dir)
            self.log(f"Processing JAR extracted from AAR")

        # Build jadx command with JVM memory options
        # Check if jadx is a JAR file or executable script
        jadx_cmd = [self.jadx_path]

        # Add JVM memory options if jadx is invoked via java
        if self.jadx_path.endswith('.jar'):
            jadx_cmd = [
                'java',
                f'-Xmx{self.jadx_memory}',
                f'-Xms{self.jadx_memory}',
                '-jar',
                self.jadx_path
            ]

        # Add jadx options
        cmd = jadx_cmd + [
            "-d", output_dir,
            "--no-res",  # Skip resources
            "--no-imports",  # Skip imports
            "--threads-count", "4",  # Use 4 threads for faster processing
            target_file
        ]

        # Set environment variable for JVM memory (works with jadx wrapper scripts)
        env = os.environ.copy()
        env['JAVA_OPTS'] = f'-Xmx{self.jadx_memory} -Xms1G'

        # Retry logic for transient failures
        last_error = None
        for attempt in range(max_retries):
            if attempt > 0:
                print(f"Retrying decompilation (attempt {attempt + 1}/{max_retries})...")
                self.log(f"Retry attempt {attempt + 1}")

            try:
                print(f"Running jadx decompilation (timeout: {self.jadx_timeout}s)...")
                self.log(f"Command: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.jadx_timeout,
                    env=env
                )

                # Check if sources were created (jadx may return non-zero even on success)
                sources_dir = os.path.join(output_dir, "sources")
                if not os.path.exists(sources_dir):
                    last_error = f"jadx failed - sources directory not found: {sources_dir}\nStderr: {result.stderr[:500]}"
                    self.log(last_error)

                    # If this is not the last attempt, clean up and retry
                    if attempt < max_retries - 1:
                        if os.path.exists(output_dir):
                            shutil.rmtree(output_dir, ignore_errors=True)
                            os.makedirs(output_dir, exist_ok=True)
                        continue
                    else:
                        raise RuntimeError(last_error)

                # Check if any Java files were decompiled
                java_files = []
                for root, dirs, files in os.walk(sources_dir):
                    java_files.extend([f for f in files if f.endswith('.java')])
                    if len(java_files) >= 10:  # Found enough files
                        break

                if len(java_files) == 0:
                    last_error = f"jadx decompilation produced no Java files\nStderr: {result.stderr[:500]}"
                    self.log(last_error)

                    # If this is not the last attempt, clean up and retry
                    if attempt < max_retries - 1:
                        if os.path.exists(output_dir):
                            shutil.rmtree(output_dir, ignore_errors=True)
                            os.makedirs(output_dir, exist_ok=True)
                        continue
                    else:
                        raise RuntimeError(last_error)

                # Success - warn about errors but continue if we have sources
                if result.returncode != 0:
                    self.log(f"jadx completed with some errors (exit code {result.returncode}) but produced {len(java_files)}+ Java files")

                print(f"✓ Decompilation successful ({len(java_files)}+ Java files)")
                self.log(f"Decompiled to {sources_dir}")
                return sources_dir

            except subprocess.TimeoutExpired as e:
                last_error = f"jadx timeout after {self.jadx_timeout} seconds ({self.jadx_timeout/60:.1f} minutes)"
                self.log(last_error)

                # Kill the process
                if hasattr(e, 'process') and e.process:
                    e.process.kill()

                # If this is not the last attempt, clean up and retry
                if attempt < max_retries - 1:
                    if os.path.exists(output_dir):
                        shutil.rmtree(output_dir, ignore_errors=True)
                        os.makedirs(output_dir, exist_ok=True)
                    continue
                else:
                    raise RuntimeError(f"{last_error}. Try increasing timeout with --jadx-timeout parameter or reducing file size.")

            except Exception as e:
                last_error = str(e)
                self.log(f"Decompilation error: {last_error}")

                # If this is not the last attempt and it's a transient error, retry
                if attempt < max_retries - 1 and not isinstance(e, (FileNotFoundError, PermissionError)):
                    if os.path.exists(output_dir):
                        shutil.rmtree(output_dir, ignore_errors=True)
                        os.makedirs(output_dir, exist_ok=True)
                    continue
                else:
                    raise

        # If we get here, all retries failed
        raise RuntimeError(f"Decompilation failed after {max_retries} attempts. Last error: {last_error}")

    def analyze_identifiers(self, sources_dir):
        """
        Analyze identifier names (classes, methods, variables)

        Returns:
            Dictionary with identifier analysis metrics
        """
        self.log("Analyzing identifiers...")

        metrics = {
            'total_classes': 0,
            'total_methods': 0,
            'total_fields': 0,
            'single_char_classes': 0,
            'single_char_methods': 0,
            'single_char_fields': 0,
            'short_classes': 0,  # Length <= 3
            'short_methods': 0,
            'short_fields': 0,
            'meaningful_classes': 0,
            'meaningful_methods': 0,
            'meaningful_fields': 0,
            'total_length_classes': 0,
            'total_length_methods': 0,
            'total_length_fields': 0,
            'obfuscated_patterns': []
        }

        # Java identifier patterns
        class_pattern = re.compile(r'(?:public|private|protected)?\s*(?:static|final|abstract)*\s*class\s+(\w+)')
        method_pattern = re.compile(r'(?:public|private|protected)?\s*(?:static|final|synchronized)*\s*\w+\s+(\w+)\s*\(')
        field_pattern = re.compile(r'(?:public|private|protected)?\s*(?:static|final)*\s*\w+\s+(\w+)\s*[=;]')

        # Walk through all Java files
        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Analyze classes
                    for match in class_pattern.finditer(content):
                        name = match.group(1)
                        metrics['total_classes'] += 1
                        metrics['total_length_classes'] += len(name)

                        if len(name) == 1:
                            metrics['single_char_classes'] += 1
                        elif len(name) <= 3:
                            metrics['short_classes'] += 1

                        if self._is_meaningful_name(name):
                            metrics['meaningful_classes'] += 1

                    # Analyze methods
                    for match in method_pattern.finditer(content):
                        name = match.group(1)
                        # Skip constructors and common names
                        if name in ['equals', 'hashCode', 'toString', 'clone', 'finalize']:
                            continue

                        metrics['total_methods'] += 1
                        metrics['total_length_methods'] += len(name)

                        if len(name) == 1:
                            metrics['single_char_methods'] += 1
                        elif len(name) <= 3:
                            metrics['short_methods'] += 1

                        if self._is_meaningful_name(name):
                            metrics['meaningful_methods'] += 1

                    # Analyze fields
                    for match in field_pattern.finditer(content):
                        name = match.group(1)
                        metrics['total_fields'] += 1
                        metrics['total_length_fields'] += len(name)

                        if len(name) == 1:
                            metrics['single_char_fields'] += 1
                        elif len(name) <= 3:
                            metrics['short_fields'] += 1

                        if self._is_meaningful_name(name):
                            metrics['meaningful_fields'] += 1

                except Exception as e:
                    self.log(f"Error reading {file_path}: {e}")

        # Calculate percentages
        if metrics['total_classes'] > 0:
            metrics['single_char_class_percentage'] = (metrics['single_char_classes'] / metrics['total_classes']) * 100
            metrics['meaningful_class_percentage'] = (metrics['meaningful_classes'] / metrics['total_classes']) * 100
            metrics['avg_class_length'] = metrics['total_length_classes'] / metrics['total_classes']

        if metrics['total_methods'] > 0:
            metrics['single_char_method_percentage'] = (metrics['single_char_methods'] / metrics['total_methods']) * 100
            metrics['meaningful_method_percentage'] = (metrics['meaningful_methods'] / metrics['total_methods']) * 100
            metrics['avg_method_length'] = metrics['total_length_methods'] / metrics['total_methods']

        if metrics['total_fields'] > 0:
            metrics['single_char_field_percentage'] = (metrics['single_char_fields'] / metrics['total_fields']) * 100
            metrics['meaningful_field_percentage'] = (metrics['meaningful_fields'] / metrics['total_fields']) * 100
            metrics['avg_field_length'] = metrics['total_length_fields'] / metrics['total_fields']

        return metrics

    def _is_meaningful_name(self, name):
        """Check if identifier name is meaningful (not obfuscated)"""
        # Convert camelCase to lowercase words
        name_lower = name.lower()

        # Check against dictionary
        if name_lower in self.dictionary_words:
            return True

        # Check for common patterns
        if len(name) > 6 and any(word in name_lower for word in self.dictionary_words):
            return True

        # Single letter or very short = not meaningful
        if len(name) <= 2:
            return False

        # Contains vowels (likely readable)
        vowel_count = sum(1 for c in name_lower if c in 'aeiou')
        if vowel_count >= 2 and len(name) >= 4:
            return True

        return False

    def check_meaningful_names(self, sources_dir):
        """Detect dictionary words in identifiers"""
        # This is integrated into analyze_identifiers
        pass

    def analyze_package_structure(self, sources_dir):
        """
        Analyze package structure and flattening

        Returns:
            Dictionary with package metrics
        """
        self.log("Analyzing package structure...")

        metrics = {
            'total_packages': 0,
            'avg_package_depth': 0,
            'max_package_depth': 0,
            'min_package_depth': 0,
            'single_level_packages': 0,
            'package_names': []
        }

        packages = set()
        depths = []

        for root, dirs, files in os.walk(sources_dir):
            # Check if directory contains Java files
            has_java = any(f.endswith('.java') for f in files)
            if has_java:
                # Calculate package path
                rel_path = os.path.relpath(root, sources_dir)
                if rel_path != '.':
                    package = rel_path.replace(os.sep, '.')
                    packages.add(package)
                    depth = package.count('.') + 1
                    depths.append(depth)

                    if depth == 1:
                        metrics['single_level_packages'] += 1

        metrics['total_packages'] = len(packages)
        metrics['package_names'] = sorted(list(packages))[:20]  # Sample

        if depths:
            metrics['avg_package_depth'] = sum(depths) / len(depths)
            metrics['max_package_depth'] = max(depths)
            metrics['min_package_depth'] = min(depths)

        return metrics

    def detect_obfuscator_tool(self, sources_dir):
        """
        Detect which obfuscator tool was likely used

        Returns:
            Dictionary with obfuscator detection results
        """
        self.log("Detecting obfuscator tool...")

        detection = {
            'detected_tool': 'Unknown',
            'confidence': 'UNKNOWN',
            'confidence_percentage': 0,
            'indicators': [],
            'tool_characteristics': {}
        }

        # Indicators for different obfuscators
        proguard_score = 0
        r8_score = 0

        # Scan files for obfuscator signatures
        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # ProGuard indicators
                    if '/* compiled from:' in content.lower() or 'sourcefile' in content.lower():
                        proguard_score += 1
                    if re.search(r'class [a-z]\d*\s*\{', content):
                        proguard_score += 1

                    # R8 indicators (similar to ProGuard but more aggressive)
                    if re.search(r'class [a-z]{1,2}\s*\{', content):
                        r8_score += 1

                except Exception as e:
                    self.log(f"Error reading {file_path}: {e}")

        # Determine most likely tool
        scores = {
            'ProGuard': proguard_score,
            'R8': r8_score
        }

        max_score = max(scores.values())
        if max_score > 0:
            detected_tool = max(scores, key=scores.get)
            detection['detected_tool'] = detected_tool
            detection['tool_characteristics'] = scores

            # Calculate confidence
            total_score = sum(scores.values())
            if total_score > 0:
                confidence_pct = (max_score / total_score) * 100
                detection['confidence_percentage'] = confidence_pct

                if confidence_pct > 70:
                    detection['confidence'] = 'HIGH'
                elif confidence_pct > 50:
                    detection['confidence'] = 'MEDIUM'
                else:
                    detection['confidence'] = 'LOW'

            # Add indicators
            if detected_tool == 'ProGuard':
                detection['indicators'].append("ProGuard naming patterns detected")
                detection['indicators'].append("Standard class name obfuscation")
            elif detected_tool == 'R8':
                detection['indicators'].append("R8 aggressive optimization detected")
                detection['indicators'].append("Short class names consistent with R8")

        return detection

    def detect_obfuscation_patterns(self, sources_dir):
        """
        Detect common obfuscation patterns (ProGuard, R8, etc.)

        Returns:
            Dictionary with detected patterns
        """
        self.log("Detecting obfuscation patterns...")

        patterns = {
            'proguard_indicators': 0,
            'sequential_naming': 0,  # a, b, c, d...
            'numeric_naming': 0,  # C0001, C0002...
            'mixed_case_obfuscation': 0,  # aA, bB, cC...
            'unicode_characters': 0,
            'similar_names_count': 0,
            'pattern_examples': [],
            'obfuscator_tool': {}  # Will store tool detection results
        }

        # Track names for pattern detection
        class_names = []

        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for ProGuard indicators
                    if 'SourceFile' in content and 'SourceFile "' in content:
                        patterns['proguard_indicators'] += 1

                    # Extract class names
                    class_pattern = re.compile(r'class\s+(\w+)')
                    for match in class_pattern.finditer(content):
                        class_names.append(match.group(1))

                    # Check for unicode characters
                    if re.search(r'[^\x00-\x7F]', content):
                        patterns['unicode_characters'] += 1

                except Exception as e:
                    self.log(f"Error reading {file_path}: {e}")

        # Analyze naming patterns
        if class_names:
            # Sequential single-letter naming (a, b, c...)
            single_letters = [n for n in class_names if len(n) == 1 and n.isalpha()]
            if len(single_letters) > 5:
                patterns['sequential_naming'] = len(single_letters)
                patterns['pattern_examples'].append(f"Sequential single letters: {', '.join(sorted(single_letters[:10]))}")

            # Numeric patterns (C0001, C0002...)
            numeric_pattern = re.compile(r'^[a-zA-Z]\d+$')
            numeric_names = [n for n in class_names if numeric_pattern.match(n)]
            if numeric_names:
                patterns['numeric_naming'] = len(numeric_names)
                patterns['pattern_examples'].append(f"Numeric naming: {', '.join(numeric_names[:5])}")

            # Mixed case (aA, bB...)
            mixed_pattern = re.compile(r'^[a-z][A-Z]$')
            mixed_names = [n for n in class_names if mixed_pattern.match(n)]
            if mixed_names:
                patterns['mixed_case_obfuscation'] = len(mixed_names)
                patterns['pattern_examples'].append(f"Mixed case: {', '.join(mixed_names[:5])}")

            # Similar names
            short_names = [n for n in class_names if len(n) <= 3]
            if len(short_names) > 10:
                patterns['similar_names_count'] = len(short_names)

        # Detect obfuscator tool
        patterns['obfuscator_tool'] = self.detect_obfuscator_tool(sources_dir)

        return patterns

    def analyze_strings(self, sources_dir):
        """
        Analyze string literals for encryption/obfuscation

        Returns:
            Dictionary with string analysis metrics and readable strings
        """
        self.log("Analyzing strings...")

        metrics = {
            'total_strings': 0,
            'encrypted_strings': 0,
            'base64_strings': 0,
            'long_random_strings': 0,
            'decryption_methods': 0,
            'avg_string_entropy': 0,
            'sample_encrypted_strings': [],
            'readable_strings': []  # New: collect readable English strings
        }

        # Patterns
        string_pattern = re.compile(r'"([^"]{3,})"')
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        decrypt_method_pattern = re.compile(r'decrypt|decode|deobfuscate|unpack', re.IGNORECASE)

        all_strings = []
        entropies = []
        readable_strings = set()  # Use set to avoid duplicates

        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Find string literals
                    for match in string_pattern.finditer(content):
                        string_value = match.group(1)
                        all_strings.append(string_value)
                        metrics['total_strings'] += 1

                        # Calculate entropy
                        entropy = self._calculate_entropy(string_value)
                        entropies.append(entropy)

                        # Check if string is readable English
                        if self._is_readable_string(string_value, entropy):
                            readable_strings.add(string_value)

                        # Check if Base64
                        if len(string_value) > 20 and base64_pattern.match(string_value):
                            metrics['base64_strings'] += 1
                            if len(metrics['sample_encrypted_strings']) < 5:
                                metrics['sample_encrypted_strings'].append(string_value[:50])

                        # High entropy = likely encrypted/random
                        elif entropy > 4.5 and len(string_value) > 20:
                            metrics['long_random_strings'] += 1
                            if len(metrics['sample_encrypted_strings']) < 5:
                                metrics['sample_encrypted_strings'].append(string_value[:50])

                    # Check for decryption methods
                    if decrypt_method_pattern.search(content):
                        metrics['decryption_methods'] += 1

                except Exception as e:
                    self.log(f"Error reading {file_path}: {e}")

        # Calculate metrics
        metrics['encrypted_strings'] = metrics['base64_strings'] + metrics['long_random_strings']

        if entropies:
            metrics['avg_string_entropy'] = sum(entropies) / len(entropies)

        if metrics['total_strings'] > 0:
            metrics['encrypted_string_percentage'] = (metrics['encrypted_strings'] / metrics['total_strings']) * 100

        # Sort and store readable strings
        metrics['readable_strings'] = sorted(list(readable_strings))

        # Detect sensitive strings from readable strings
        metrics['sensitive_strings'] = self._detect_sensitive_strings(list(readable_strings))

        return metrics

    def _is_readable_string(self, string, entropy=None):
        """
        Check if a string appears to be readable English text

        Args:
            string: The string to check
            entropy: Pre-calculated entropy (optional)

        Returns:
            True if string appears readable, False otherwise
        """
        # Skip very short strings
        if len(string) < 4:
            return False

        # Calculate entropy if not provided
        if entropy is None:
            entropy = self._calculate_entropy(string)

        # High entropy = likely encrypted/obfuscated
        if entropy > 4.5:
            return False

        # Check for mostly ASCII printable characters
        printable_count = sum(1 for c in string if c.isprintable() and ord(c) < 128)
        if printable_count < len(string) * 0.9:
            return False

        # Check for vowels (English text has vowels)
        vowels = sum(1 for c in string.lower() if c in 'aeiou')
        if vowels < len(string) * 0.15:  # At least 15% vowels
            return False

        # Check for reasonable mix of letters and other chars
        letters = sum(1 for c in string if c.isalpha())
        if letters < len(string) * 0.5:  # At least 50% letters
            return False

        # Avoid code-like patterns
        if string.count('(') > 2 or string.count('{') > 1 or string.count('[') > 2:
            return False

        # Avoid Base64-like strings
        if len(string) > 20 and re.match(r'^[A-Za-z0-9+/]+=*$', string):
            return False

        return True

    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0

        # Count character frequencies
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        length = len(string)
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _detect_sensitive_strings(self, strings_list):
        """
        Detect sensitive strings that should be obfuscated

        Args:
            strings_list: List of strings to analyze

        Returns:
            Dictionary categorizing sensitive strings
        """
        sensitive = {
            'api_keys': [],
            'urls': [],
            'package_names': [],
            'email_addresses': [],
            'ip_addresses': [],
            'secrets': [],
            'database_strings': [],
            'total_sensitive': 0
        }

        # Regex patterns for sensitive data
        api_key_patterns = [
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'(?i)aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]', 'AWS Secret Key'),
            # Google
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google API Key'),
            # Firebase
            (r'(?i)firebase.{0,20}[\'"][0-9a-zA-Z-_]{20,}[\'"]', 'Firebase Key'),
            # Generic API key patterns
            (r'(?i)api[_-]?key.{0,10}[\'"][0-9a-zA-Z]{16,}[\'"]', 'Generic API Key'),
            (r'(?i)apikey.{0,10}[\'"][0-9a-zA-Z]{16,}[\'"]', 'Generic API Key'),
            # Authorization tokens
            (r'(?i)bearer.{0,10}[0-9a-zA-Z._-]{20,}', 'Bearer Token'),
            (r'(?i)token.{0,10}[\'"][0-9a-zA-Z._-]{20,}[\'"]', 'Auth Token'),
            # Secret keys
            (r'(?i)secret.{0,10}[\'"][0-9a-zA-Z._-]{16,}[\'"]', 'Secret Key'),
            (r'(?i)private.?key.{0,10}[\'"][0-9a-zA-Z._-]{16,}[\'"]', 'Private Key'),
        ]

        # URL pattern
        url_pattern = re.compile(r'https?://[a-zA-Z0-9][a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=%]{8,}')

        # Package name pattern (Java/Android)
        package_pattern = re.compile(r'\b[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}\b')

        # Email pattern
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

        # IP address pattern
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

        # Database connection strings
        db_patterns = [
            r'(?i)jdbc:[a-z]+://',
            r'(?i)mongodb://',
            r'(?i)postgres://',
            r'(?i)mysql://',
            r'(?i)password.{0,10}[\'"][^\'"]{3,}[\'"]',
            r'(?i)pwd.{0,10}[\'"][^\'"]{3,}[\'"]',
        ]

        for string in strings_list:
            is_sensitive = False

            # Check for API keys
            for pattern, key_type in api_key_patterns:
                if re.search(pattern, string):
                    sensitive['api_keys'].append({
                        'string': string[:100],  # Truncate long strings
                        'type': key_type
                    })
                    is_sensitive = True
                    break

            # Check for URLs
            if url_pattern.search(string):
                sensitive['urls'].append(string[:150])
                is_sensitive = True

            # Check for package names (only if looks like Android/Java package)
            pkg_match = package_pattern.search(string)
            if pkg_match and not is_sensitive:
                pkg = pkg_match.group(0)
                # Filter out common false positives
                if len(pkg) > 10 and '.' in pkg and not any(x in pkg for x in ['example', 'test', 'demo']):
                    sensitive['package_names'].append(pkg)
                    is_sensitive = True

            # Check for emails
            if email_pattern.search(string):
                sensitive['email_addresses'].append(string[:100])
                is_sensitive = True

            # Check for IP addresses
            if ip_pattern.search(string):
                sensitive['ip_addresses'].append(string[:50])
                is_sensitive = True

            # Check for database strings
            for db_pattern in db_patterns:
                if re.search(db_pattern, string):
                    sensitive['database_strings'].append(string[:100])
                    is_sensitive = True
                    break

            # Check for generic secrets (long alphanumeric strings)
            if not is_sensitive and len(string) > 20:
                # High ratio of alphanumeric, likely a key/token
                alnum = sum(1 for c in string if c.isalnum())
                if alnum / len(string) > 0.9 and not string.isdigit():
                    # Check if it looks like a key (mixed case, numbers)
                    has_upper = any(c.isupper() for c in string)
                    has_lower = any(c.islower() for c in string)
                    has_digit = any(c.isdigit() for c in string)

                    if has_upper and has_lower and has_digit:
                        sensitive['secrets'].append(string[:100])
                        is_sensitive = True

        # Remove duplicates and count
        for key in sensitive:
            if isinstance(sensitive[key], list) and key != 'total_sensitive':
                # Keep unique entries
                if key == 'api_keys':
                    seen = set()
                    unique = []
                    for item in sensitive[key]:
                        if item['string'] not in seen:
                            seen.add(item['string'])
                            unique.append(item)
                    sensitive[key] = unique
                else:
                    sensitive[key] = list(set(sensitive[key]))

        # Calculate total
        sensitive['total_sensitive'] = sum(
            len(v) for k, v in sensitive.items()
            if k != 'total_sensitive' and isinstance(v, list)
        )

        return sensitive

    def analyze_control_flow(self, sources_dir):
        """
        Analyze control flow complexity (cyclomatic complexity)

        Returns:
            Dictionary with complexity metrics
        """
        self.log("Analyzing control flow complexity...")

        metrics = {
            'total_methods': 0,
            'total_complexity': 0,
            'avg_complexity': 0,
            'max_complexity': 0,
            'high_complexity_methods': 0,  # Complexity > 10
            'dead_code_indicators': 0,
            'goto_statements': 0,
            'complex_method_samples': []
        }

        method_pattern = re.compile(r'(\w+)\s*\([^)]*\)\s*\{')

        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Simple cyclomatic complexity estimation
                    # Count decision points: if, while, for, case, catch, &&, ||
                    complexity = 1  # Base complexity
                    complexity += content.count('if ')
                    complexity += content.count('while ')
                    complexity += content.count('for ')
                    complexity += content.count('case ')
                    complexity += content.count('catch ')
                    complexity += content.count(' && ')
                    complexity += content.count(' || ')
                    complexity += content.count('? ')  # Ternary operator

                    methods_in_file = len(method_pattern.findall(content))
                    if methods_in_file > 0:
                        metrics['total_methods'] += methods_in_file
                        avg_complexity_in_file = complexity / methods_in_file
                        metrics['total_complexity'] += complexity

                        if avg_complexity_in_file > metrics['max_complexity']:
                            metrics['max_complexity'] = avg_complexity_in_file

                        if avg_complexity_in_file > 10:
                            metrics['high_complexity_methods'] += methods_in_file
                            if len(metrics['complex_method_samples']) < 5:
                                rel_path = os.path.relpath(file_path, sources_dir)
                                metrics['complex_method_samples'].append(
                                    f"{rel_path} (complexity: {avg_complexity_in_file:.1f})"
                                )

                    # Check for goto (rare but indicates obfuscation)
                    if 'goto ' in content:
                        metrics['goto_statements'] += content.count('goto ')

                    # Dead code indicators
                    if 'return;' in content or 'throw ' in content:
                        # Count unreachable code patterns
                        lines = content.split('\n')
                        for i, line in enumerate(lines):
                            if 'return' in line or 'throw ' in line:
                                # Check if there's code after in same block
                                if i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].strip().startswith('}'):
                                    metrics['dead_code_indicators'] += 1

                except Exception as e:
                    self.log(f"Error reading {file_path}: {e}")

        if metrics['total_methods'] > 0:
            metrics['avg_complexity'] = metrics['total_complexity'] / metrics['total_methods']

        return metrics

    def _check_release_readiness(self, analysis, expected_obfuscator=None, min_score=40):
        """
        Check if APK/AAR is ready for release based on obfuscation

        Args:
            analysis: Analysis results dictionary
            expected_obfuscator: Expected obfuscator tool name (ProGuard, R8, None)
            min_score: Minimum obfuscation score required (default: 40)

        Returns:
            Dictionary with release readiness assessment
        """
        obfuscation_assessment = self._assess_obfuscation_likelihood(analysis)
        detected_tool = analysis['patterns'].get('obfuscator_tool', {})

        readiness = {
            'ready_for_release': False,
            'confidence': 'LOW',
            'warnings': [],
            'blockers': [],
            'recommendations': [],
            'obfuscation_score': obfuscation_assessment['score'],
            'expected_obfuscator': expected_obfuscator,
            'detected_obfuscator': detected_tool.get('detected_tool', 'Unknown'),
            'tool_match': False
        }

        # Check obfuscation score
        if obfuscation_assessment['score'] < min_score:
            readiness['blockers'].append(
                f"Obfuscation score ({obfuscation_assessment['score']:.1f}) is below minimum required ({min_score})"
            )
            readiness['recommendations'].append(
                "Enable or strengthen obfuscation settings before release"
            )
            readiness['recommendations'].append(
                "Consider Digital.ai Android Protection (https://digital.ai/mobile-app-obfuscation) for enterprise-grade security and advanced obfuscation"
            )
        # Recommend higher scores for high-security applications
        elif obfuscation_assessment['score'] >= 40 and obfuscation_assessment['score'] < 50:
            readiness['recommendations'].append(
                "For high-security applications (banking, healthcare, etc.), consider aiming for a score of 50 or above"
            )

        # Inform about advanced protection capabilities beyond basic obfuscation
        readiness['recommendations'].append(
            "Note: Basic obfuscation tools don't provide runtime protection. For RASP (Runtime Application Self-Protection), "
            "root/jailbreak detection, or anti-debugging capabilities, evaluate solutions like Digital.ai Android Protection "
            "(https://digital.ai/mobile-app-obfuscation)"
        )

        # Check if expected obfuscator was used
        if expected_obfuscator:
            if detected_tool.get('detected_tool', 'Unknown').lower() == expected_obfuscator.lower():
                readiness['tool_match'] = True
                readiness['recommendations'].append(
                    f"✓ Confirmed: {expected_obfuscator} obfuscation detected"
                )
            else:
                readiness['blockers'].append(
                    f"Expected {expected_obfuscator} but detected {detected_tool.get('detected_tool', 'Unknown')}"
                )
                readiness['recommendations'].append(
                    f"Verify {expected_obfuscator} is properly configured in your build"
                )

        # Check for unobfuscated indicators
        ident = analysis['identifiers']
        if ident.get('meaningful_class_percentage', 0) > 60:
            readiness['warnings'].append(
                f"High percentage of meaningful class names ({ident['meaningful_class_percentage']:.1f}%)"
            )

        strings = analysis['strings']
        if strings.get('encrypted_string_percentage', 0) == 0:
            readiness['warnings'].append(
                "No string encryption detected - sensitive data may be exposed"
            )

        # Check for sensitive strings
        sensitive_strings = strings.get('sensitive_strings', {})
        total_sensitive = sensitive_strings.get('total_sensitive', 0)

        if total_sensitive > 0:
            readiness['blockers'].append(
                f"Found {total_sensitive} sensitive strings that should be obfuscated (API keys, URLs, secrets, etc.)"
            )
            readiness['recommendations'].append(
                "Remove or obfuscate sensitive strings before release - they are currently visible in plain text"
            )

            # Add specific warnings for each type
            if len(sensitive_strings.get('api_keys', [])) > 0:
                readiness['blockers'].append(
                    f"Exposed API keys detected ({len(sensitive_strings['api_keys'])} found) - CRITICAL SECURITY RISK"
                )

            if len(sensitive_strings.get('urls', [])) > 0:
                readiness['warnings'].append(
                    f"Exposed URLs detected ({len(sensitive_strings['urls'])} found) - may reveal API endpoints"
                )

            if len(sensitive_strings.get('database_strings', [])) > 0:
                readiness['blockers'].append(
                    f"Database connection strings detected ({len(sensitive_strings['database_strings'])} found) - CRITICAL SECURITY RISK"
                )

        # Determine overall readiness
        has_blockers = len(readiness['blockers']) > 0
        has_warnings = len(readiness['warnings']) > 0

        if not has_blockers and not has_warnings:
            readiness['ready_for_release'] = True
            readiness['confidence'] = 'HIGH'
        elif not has_blockers:
            readiness['ready_for_release'] = True
            readiness['confidence'] = 'MEDIUM'
        else:
            readiness['ready_for_release'] = False
            readiness['confidence'] = 'LOW'

        return readiness

    def _assess_obfuscation_likelihood(self, analysis):
        """
        Assess likelihood of obfuscation based on absolute metrics

        Args:
            analysis: Analysis results dictionary

        Returns:
            Dictionary with obfuscation likelihood assessment and score
        """
        ident = analysis['identifiers']
        strings = analysis['strings']
        patterns = analysis['patterns']
        cf = analysis['control_flow']

        # Score from 0-100 based on obfuscation indicators
        score = 0
        indicators = []

        # Identifier analysis (40 points)
        if ident['total_classes'] > 0:
            single_char_pct = ident.get('single_char_class_percentage', 0)
            meaningful_pct = ident.get('meaningful_class_percentage', 0)
            avg_length = ident.get('avg_class_length', 10)

            # High single-char percentage = likely obfuscated
            if single_char_pct > 50:
                score += 20
                indicators.append(f"Very high single-character class names ({single_char_pct:.1f}%)")
            elif single_char_pct > 30:
                score += 15
                indicators.append(f"High single-character class names ({single_char_pct:.1f}%)")
            elif single_char_pct > 10:
                score += 10
                indicators.append(f"Moderate single-character class names ({single_char_pct:.1f}%)")

            # Low meaningful percentage = likely obfuscated
            if meaningful_pct < 20:
                score += 15
                indicators.append(f"Very low meaningful class names ({meaningful_pct:.1f}%)")
            elif meaningful_pct < 40:
                score += 10
                indicators.append(f"Low meaningful class names ({meaningful_pct:.1f}%)")

            # Short average length = likely obfuscated
            if avg_length < 3:
                score += 5
                indicators.append(f"Very short average class name length ({avg_length:.1f})")
            elif avg_length < 5:
                score += 3
                indicators.append(f"Short average class name length ({avg_length:.1f})")

        # String analysis (30 points)
        if strings['total_strings'] > 0:
            encrypted_pct = strings.get('encrypted_string_percentage', 0)

            if encrypted_pct > 30:
                score += 20
                indicators.append(f"High encrypted string percentage ({encrypted_pct:.1f}%)")
            elif encrypted_pct > 10:
                score += 10
                indicators.append(f"Moderate encrypted string percentage ({encrypted_pct:.1f}%)")

            if strings.get('decryption_methods', 0) > 0:
                score += 10
                indicators.append(f"Decryption methods detected ({strings['decryption_methods']} found)")

        # Obfuscation patterns (20 points)
        if patterns.get('sequential_naming', 0) > 10:
            score += 10
            indicators.append(f"Sequential single-letter naming detected ({patterns['sequential_naming']} classes)")
        elif patterns.get('sequential_naming', 0) > 5:
            score += 5
            indicators.append(f"Some sequential naming detected ({patterns['sequential_naming']} classes)")

        if patterns.get('numeric_naming', 0) > 0:
            score += 5
            indicators.append(f"Numeric naming pattern detected ({patterns['numeric_naming']} classes)")

        if patterns.get('proguard_indicators', 0) > 0:
            score += 5
            indicators.append(f"ProGuard indicators found ({patterns['proguard_indicators']} files)")

        # Control flow (10 points)
        if cf.get('avg_complexity', 0) > 10:
            score += 5
            indicators.append(f"High average complexity ({cf['avg_complexity']:.1f})")

        if cf.get('goto_statements', 0) > 0:
            score += 5
            indicators.append(f"Goto statements detected ({cf['goto_statements']} found)")

        # Cap score at 100
        score = min(score, 100)

        # Determine likelihood
        if score >= 70:
            likelihood = "VERY HIGH"
            assessment = "Strong obfuscation detected"
        elif score >= 50:
            likelihood = "HIGH"
            assessment = "Likely obfuscated"
        elif score >= 30:
            likelihood = "MODERATE"
            assessment = "Possibly obfuscated"
        elif score >= 15:
            likelihood = "LOW"
            assessment = "Minimal obfuscation"
        else:
            likelihood = "VERY LOW"
            assessment = "Appears unobfuscated"

        return {
            'likelihood': likelihood,
            'score': score,
            'assessment': assessment,
            'indicators': indicators
        }

    def analyze_single_file(self, file_path, output_dir="./results", expected_obfuscator=None, min_score=40):
        """
        Analyze a single APK/AAR file for obfuscation without comparison

        Args:
            file_path: Path to APK or AAR file
            output_dir: Directory for results
            expected_obfuscator: Expected obfuscator tool (ProGuard, R8, etc.)
            min_score: Minimum obfuscation score required for release (default: 40)

        Returns:
            Dictionary with analysis results
        """
        print(f"\n{'='*60}")
        print("APK/AAR Obfuscation Analyzer (Single File Mode)")
        print(f"{'='*60}\n")

        # Extract file metadata (hashes and signature)
        print("Extracting file metadata...")
        file_metadata = {
            'file_name': os.path.basename(file_path),
            'file_path': os.path.abspath(file_path),
            'file_size_bytes': os.path.getsize(file_path),
            'file_size_mb': round(os.path.getsize(file_path) / (1024 * 1024), 2),
            'hashes': self._calculate_file_hashes(file_path),
            'signature': self._extract_signature_info(file_path)
        }

        # Create temp directory for decompilation
        with tempfile.TemporaryDirectory() as temp_dir:
            file_dir = os.path.join(temp_dir, "analysis")

            # Decompile file
            print("Decompiling file...")
            sources = self.decompile_apk(file_path, file_dir)

            # Analyze
            print("\nAnalyzing file...")
            analysis = {
                'identifiers': self.analyze_identifiers(sources),
                'packages': self.analyze_package_structure(sources),
                'patterns': self.detect_obfuscation_patterns(sources),
                'strings': self.analyze_strings(sources),
                'control_flow': self.analyze_control_flow(sources)
            }

            # Assess obfuscation likelihood
            print("\nAssessing obfuscation likelihood...")
            obfuscation_assessment = self._assess_obfuscation_likelihood(analysis)

            # Check release readiness
            print("Checking release readiness...")
            release_readiness = self._check_release_readiness(analysis, expected_obfuscator, min_score)

            # Create result structure
            result = {
                'timestamp': datetime.now().isoformat(),
                'file_metadata': file_metadata,
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'analysis': analysis,
                'obfuscation_assessment': obfuscation_assessment,
                'release_readiness': release_readiness
            }

            # Create output directory
            os.makedirs(output_dir, exist_ok=True)

            # Generate reports
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # JSON report
            json_report_path = os.path.join(output_dir, f"single_analysis_{timestamp}.json")
            with open(json_report_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\nJSON report saved: {json_report_path}")

            # HTML report
            html_report_path = os.path.join(output_dir, f"single_report_{timestamp}.html")
            self._create_single_html_report(result, html_report_path)
            print(f"HTML report saved: {html_report_path}")

            # Save readable strings to file
            readable_strings = analysis['strings'].get('readable_strings', [])
            if readable_strings:
                strings_file_path = os.path.join(output_dir, f"readable_strings_{timestamp}.txt")
                with open(strings_file_path, 'w', encoding='utf-8') as f:
                    for string in readable_strings:
                        f.write(f"{string}\n")
                print(f"Readable strings saved: {strings_file_path} ({len(readable_strings)} strings)")

            # Save sensitive strings to file
            sensitive_strings = analysis['strings'].get('sensitive_strings', {})
            total_sensitive = sensitive_strings.get('total_sensitive', 0)
            if total_sensitive > 0:
                sensitive_file_path = os.path.join(output_dir, f"sensitive_strings_{timestamp}.json")
                with open(sensitive_file_path, 'w', encoding='utf-8') as f:
                    json.dump(sensitive_strings, f, indent=2, default=str)
                print(f"Sensitive strings saved: {sensitive_file_path} ({total_sensitive} sensitive strings found)")

            # Print summary
            self._print_single_summary(result)

            return result

    def _create_single_html_report(self, result, output_path):
        """Generate HTML report for single file analysis"""
        assessment = result['obfuscation_assessment']
        analysis = result['analysis']
        readiness = result.get('release_readiness', {})
        tool_info = analysis['patterns'].get('obfuscator_tool', {})
        file_metadata = result.get('file_metadata', {})
        sensitive_strings = analysis['strings'].get('sensitive_strings', {})

        # Determine score class
        if assessment['score'] >= 70:
            score_class = 'score-high'
        elif assessment['score'] >= 30:
            score_class = 'score-medium'
        else:
            score_class = 'score-low'

        # Build obfuscator detection section
        obfuscator_html = ""
        if tool_info.get('detected_tool') != 'Unknown':
            conf_color = '#4caf50' if tool_info.get('confidence') == 'HIGH' else '#ff9800' if tool_info.get('confidence') == 'MEDIUM' else '#f44336'
            obfuscator_html = f"""
        <div class="obfuscator-detection">
            <h3>🔍 Detected Obfuscator</h3>
            <div class="tool-name">{tool_info['detected_tool']}</div>
            <div style="color: {conf_color}; font-weight: bold;">
                Confidence: {tool_info.get('confidence', 'UNKNOWN')} ({tool_info.get('confidence_percentage', 0):.1f}%)
            </div>
        </div>
"""

        # Build release readiness section
        readiness_html = ""
        if readiness:
            ready_status = "✓ READY FOR RELEASE" if readiness['ready_for_release'] else "✗ NOT READY FOR RELEASE"
            ready_color = '#4caf50' if readiness['ready_for_release'] else '#f44336'

            blockers_html = ""
            if readiness['blockers']:
                blockers_html = "<h4>⚠ Blockers (Must Fix):</h4><ul>"
                blockers_html += "".join([f'<li style="color: #f44336;">{b}</li>' for b in readiness['blockers']])
                blockers_html += "</ul>"

            warnings_html = ""
            if readiness['warnings']:
                warnings_html = "<h4>⚠ Warnings:</h4><ul>"
                warnings_html += "".join([f'<li style="color: #ff9800;">{w}</li>' for w in readiness['warnings']])
                warnings_html += "</ul>"

            recommendations_html = ""
            if readiness['recommendations']:
                recommendations_html = "<h4>📋 Recommendations:</h4><ul>"
                recommendations_html += "".join([f'<li>{r}</li>' for r in readiness['recommendations']])
                recommendations_html += "</ul>"

            tool_match_html = ""
            if readiness.get('expected_obfuscator'):
                match_symbol = "✓" if readiness['tool_match'] else "✗"
                match_color = '#4caf50' if readiness['tool_match'] else '#f44336'
                tool_match_html = f"""
                <div style="margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 4px;">
                    <span style="color: {match_color}; font-weight: bold;">{match_symbol}</span>
                    Expected: {readiness['expected_obfuscator']}, Detected: {readiness['detected_obfuscator']}
                </div>
"""

            readiness_html = f"""
        <div class="release-readiness">
            <h2>📱 Release Readiness Check</h2>
            <div style="font-size: 24px; font-weight: bold; color: {ready_color}; margin: 15px 0;">
                {ready_status}
            </div>
            <div style="font-weight: bold; margin: 10px 0;">
                Confidence: {readiness['confidence']}
            </div>
            {tool_match_html}
            {blockers_html}
            {warnings_html}
            {recommendations_html}
        </div>
"""

        indicators_html = "".join([f'<li>{ind}</li>' for ind in assessment['indicators']])
        if not indicators_html:
            indicators_html = "<li>No strong obfuscation indicators found</li>"

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>APK/AAR Obfuscation Analysis - Single File</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .score {{
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            padding: 30px;
            margin: 20px 0;
            border-radius: 8px;
            color: white;
        }}
        .score-low {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .score-medium {{ background: linear-gradient(135deg, #ffd89b 0%, #19547b 100%); }}
        .score-high {{ background: linear-gradient(135deg, #89f7fe 0%, #66a6ff 100%); }}
        .assessment {{
            padding: 20px;
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .assessment h3 {{
            margin-top: 0;
            color: #1976d2;
        }}
        .metric {{
            display: inline-block;
            padding: 5px 10px;
            margin: 5px;
            background-color: #ecf0f1;
            border-radius: 4px;
        }}
        .indicators {{
            background-color: #fff3e0;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }}
        .indicators ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .indicators li {{
            margin: 5px 0;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
            text-align: center;
        }}
        .file-info {{
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }}
        .obfuscator-detection {{
            background-color: #e3f2fd;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #2196f3;
        }}
        .tool-name {{
            font-size: 28px;
            font-weight: bold;
            color: #1976d2;
            margin: 10px 0;
        }}
        .release-readiness {{
            background-color: #f5f5f5;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #ff9800;
        }}
        .sensitive-strings-warning {{
            background-color: #ffebee;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #d32f2f;
        }}
        .sensitive-strings-safe {{
            background-color: #e8f5e9;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #4caf50;
        }}
        .sensitive-category {{
            margin: 15px 0;
            padding: 15px;
            border-radius: 4px;
        }}
        .sensitive-category.critical {{
            background-color: #ffcdd2;
            border-left: 3px solid #d32f2f;
        }}
        .sensitive-category.warning {{
            background-color: #fff9c4;
            border-left: 3px solid #fbc02d;
        }}
        .sensitive-category.info {{
            background-color: #e3f2fd;
            border-left: 3px solid #1976d2;
        }}
        .sensitive-category h4 {{
            margin-top: 0;
        }}
        .sensitive-category code {{
            background-color: rgba(0,0,0,0.05);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 14px;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>APK/AAR Obfuscation Analysis - Single File</h1>
        <p class="timestamp">Generated: {result['timestamp']}</p>

        <div class="file-info">
            <strong>File:</strong> {result['file_name']}
        </div>

{self._format_metadata_html(file_metadata)}

{obfuscator_html}

        <div class="score {score_class}">
            Obfuscation Likelihood: {assessment['likelihood']}<br>
            <span style="font-size: 36px;">Score: {assessment['score']:.1f}/100</span>
        </div>

        <div class="assessment">
            <h3>{assessment['assessment']}</h3>
        </div>

{readiness_html}

        <div class="indicators">
            <h3>Obfuscation Indicators Detected:</h3>
            <ul>
{indicators_html}
            </ul>
        </div>

        <h2>Sensitive Strings Analysis</h2>
        {self._format_sensitive_strings_html(sensitive_strings)}

        <h2>Identifier Analysis</h2>
        {self._format_metrics(analysis['identifiers'])}

        <h2>String Analysis</h2>
        {self._format_metrics(analysis['strings'])}

        <h2>Control Flow Complexity</h2>
        {self._format_metrics(analysis['control_flow'])}

        <h2>Package Structure</h2>
        {self._format_metrics(analysis['packages'])}

        <h2>Obfuscation Patterns</h2>
        {self._format_metrics(analysis['patterns'])}
    </div>
</body>
</html>
"""
        with open(output_path, 'w') as f:
            f.write(html)

    def _print_single_summary(self, result):
        """Print summary for single file analysis"""
        assessment = result['obfuscation_assessment']
        readiness = result.get('release_readiness', {})
        tool_info = result['analysis']['patterns'].get('obfuscator_tool', {})
        metadata = result.get('file_metadata', {})

        print(f"\n{'='*60}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*60}\n")

        print(f"File: {result['file_name']}")

        # Display key file identification info
        if metadata:
            hashes = metadata.get('hashes', {})
            if hashes and 'sha256' in hashes:
                print(f"SHA256: {hashes['sha256']}")

            signature = metadata.get('signature', {})
            if signature and not signature.get('note'):
                if signature.get('signed'):
                    schemes = []
                    if signature.get('v1_signed'):
                        schemes.append('v1')
                    if signature.get('v2_signed'):
                        schemes.append('v2')
                    if signature.get('v3_signed'):
                        schemes.append('v3')
                    schemes_str = ', '.join(schemes) if schemes else 'Unknown'
                    print(f"Signature: Signed ({schemes_str})")
                else:
                    print(f"Signature: Not signed")

        # Obfuscator detection
        if tool_info.get('detected_tool') != 'Unknown':
            print(f"\nDetected Obfuscator: {tool_info['detected_tool']}")
            print(f"Detection Confidence: {tool_info.get('confidence', 'UNKNOWN')} ({tool_info.get('confidence_percentage', 0):.1f}%)")

        # Obfuscation assessment
        print(f"\nObfuscation Likelihood: {assessment['likelihood']}")
        print(f"Score: {assessment['score']:.1f}/100")
        print(f"Assessment: {assessment['assessment']}")

        # Release readiness
        if readiness:
            print(f"\n{'='*60}")
            print("RELEASE READINESS CHECK")
            print(f"{'='*60}\n")

            status_symbol = "✓" if readiness['ready_for_release'] else "✗"
            status_text = "READY FOR RELEASE" if readiness['ready_for_release'] else "NOT READY FOR RELEASE"
            print(f"{status_symbol} Status: {status_text}")
            print(f"Confidence: {readiness['confidence']}")

            if readiness.get('expected_obfuscator'):
                tool_match = "✓" if readiness['tool_match'] else "✗"
                print(f"{tool_match} Expected: {readiness['expected_obfuscator']}, Detected: {readiness['detected_obfuscator']}")

            if readiness['blockers']:
                print("\n⚠ BLOCKERS (Must fix before release):")
                for i, blocker in enumerate(readiness['blockers'], 1):
                    print(f"  {i}. {blocker}")

            if readiness['warnings']:
                print("\n⚠ WARNINGS:")
                for i, warning in enumerate(readiness['warnings'], 1):
                    print(f"  {i}. {warning}")

            if readiness['recommendations']:
                print("\n📋 RECOMMENDATIONS:")
                for i, rec in enumerate(readiness['recommendations'], 1):
                    print(f"  {i}. {rec}")

        if assessment['indicators']:
            print(f"\n{'='*60}")
            print("OBFUSCATION INDICATORS")
            print(f"{'='*60}\n")
            for i, indicator in enumerate(assessment['indicators'], 1):
                print(f"  {i}. {indicator}")

        print(f"\n{'='*60}\n")

    def compare_apks(self, original_apk, obfuscated_apk=None, output_dir="./results", expected_obfuscator=None, min_score=40):
        """
        Compare original and obfuscated APKs/AARs, or analyze a single file

        Args:
            original_apk: Path to original APK/AAR (or single file to analyze)
            obfuscated_apk: Path to obfuscated APK/AAR (optional)
            output_dir: Directory for results
            expected_obfuscator: Expected obfuscator tool (for single-file mode)
            min_score: Minimum obfuscation score (for single-file mode)

        Returns:
            Dictionary with comparison results
        """
        # If no second file provided, use single-file analysis mode
        if obfuscated_apk is None:
            return self.analyze_single_file(original_apk, output_dir, expected_obfuscator, min_score)

        print(f"\n{'='*60}")
        print("APK/AAR Obfuscation Analyzer (Comparison Mode)")
        print(f"{'='*60}\n")

        # Extract file metadata for both files
        print("Extracting file metadata...")
        original_metadata = {
            'file_name': os.path.basename(original_apk),
            'file_path': os.path.abspath(original_apk),
            'file_size_bytes': os.path.getsize(original_apk),
            'file_size_mb': round(os.path.getsize(original_apk) / (1024 * 1024), 2),
            'hashes': self._calculate_file_hashes(original_apk),
            'signature': self._extract_signature_info(original_apk)
        }

        obfuscated_metadata = {
            'file_name': os.path.basename(obfuscated_apk),
            'file_path': os.path.abspath(obfuscated_apk),
            'file_size_bytes': os.path.getsize(obfuscated_apk),
            'file_size_mb': round(os.path.getsize(obfuscated_apk) / (1024 * 1024), 2),
            'hashes': self._calculate_file_hashes(obfuscated_apk),
            'signature': self._extract_signature_info(obfuscated_apk)
        }

        # Create temp directories for decompilation
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.path.join(temp_dir, "original")
            obfuscated_dir = os.path.join(temp_dir, "obfuscated")

            # Decompile both files
            print("Decompiling files...")
            original_sources = self.decompile_apk(original_apk, original_dir)
            obfuscated_sources = self.decompile_apk(obfuscated_apk, obfuscated_dir)

            # Analyze both versions
            print("\nAnalyzing original file...")
            original_analysis = {
                'identifiers': self.analyze_identifiers(original_sources),
                'packages': self.analyze_package_structure(original_sources),
                'patterns': self.detect_obfuscation_patterns(original_sources),
                'strings': self.analyze_strings(original_sources),
                'control_flow': self.analyze_control_flow(original_sources)
            }

            print("Analyzing obfuscated file...")
            obfuscated_analysis = {
                'identifiers': self.analyze_identifiers(obfuscated_sources),
                'packages': self.analyze_package_structure(obfuscated_sources),
                'patterns': self.detect_obfuscation_patterns(obfuscated_sources),
                'strings': self.analyze_strings(obfuscated_sources),
                'control_flow': self.analyze_control_flow(obfuscated_sources)
            }

            # Calculate obfuscation score
            print("\nCalculating obfuscation effectiveness...")
            comparison = self._calculate_comparison(original_analysis, obfuscated_analysis)

            # Add file metadata to comparison
            comparison['original_metadata'] = original_metadata
            comparison['obfuscated_metadata'] = obfuscated_metadata

            # Create output directory
            os.makedirs(output_dir, exist_ok=True)

            # Generate reports
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # JSON report
            json_report_path = os.path.join(output_dir, f"analysis_{timestamp}.json")
            self._save_json_report(comparison, json_report_path)
            print(f"\nJSON report saved: {json_report_path}")

            # HTML report
            html_report_path = os.path.join(output_dir, f"report_{timestamp}.html")
            self._create_html_report(comparison, html_report_path)
            print(f"HTML report saved: {html_report_path}")

            # Save readable strings to files
            orig_readable_strings = original_analysis['strings'].get('readable_strings', [])
            obf_readable_strings = obfuscated_analysis['strings'].get('readable_strings', [])

            if orig_readable_strings:
                orig_strings_file = os.path.join(output_dir, f"readable_strings_original_{timestamp}.txt")
                with open(orig_strings_file, 'w', encoding='utf-8') as f:
                    for string in orig_readable_strings:
                        f.write(f"{string}\n")
                print(f"Original readable strings saved: {orig_strings_file} ({len(orig_readable_strings)} strings)")

            if obf_readable_strings:
                obf_strings_file = os.path.join(output_dir, f"readable_strings_obfuscated_{timestamp}.txt")
                with open(obf_strings_file, 'w', encoding='utf-8') as f:
                    for string in obf_readable_strings:
                        f.write(f"{string}\n")
                print(f"Obfuscated readable strings saved: {obf_strings_file} ({len(obf_readable_strings)} strings)")

            # Save sensitive strings to files
            orig_sensitive_strings = original_analysis['strings'].get('sensitive_strings', {})
            obf_sensitive_strings = obfuscated_analysis['strings'].get('sensitive_strings', {})

            orig_total_sensitive = orig_sensitive_strings.get('total_sensitive', 0)
            obf_total_sensitive = obf_sensitive_strings.get('total_sensitive', 0)

            if orig_total_sensitive > 0:
                orig_sensitive_file = os.path.join(output_dir, f"sensitive_strings_original_{timestamp}.json")
                with open(orig_sensitive_file, 'w', encoding='utf-8') as f:
                    json.dump(orig_sensitive_strings, f, indent=2, default=str)
                print(f"Original sensitive strings saved: {orig_sensitive_file} ({orig_total_sensitive} sensitive strings)")

            if obf_total_sensitive > 0:
                obf_sensitive_file = os.path.join(output_dir, f"sensitive_strings_obfuscated_{timestamp}.json")
                with open(obf_sensitive_file, 'w', encoding='utf-8') as f:
                    json.dump(obf_sensitive_strings, f, indent=2, default=str)
                print(f"Obfuscated sensitive strings saved: {obf_sensitive_file} ({obf_total_sensitive} sensitive strings)")

            # Print summary
            self._print_summary(comparison)

            return comparison

    def _calculate_comparison(self, original, obfuscated):
        """Calculate obfuscation effectiveness score"""
        # Calculate individual obfuscation scores for both files
        original_obfuscation = self._assess_obfuscation_likelihood(original)
        obfuscated_obfuscation = self._assess_obfuscation_likelihood(obfuscated)

        comparison = {
            'timestamp': datetime.now().isoformat(),
            'original': original,
            'obfuscated': obfuscated,
            'original_obfuscation_score': original_obfuscation['score'],
            'obfuscated_obfuscation_score': obfuscated_obfuscation['score'],
            'changes': {},
            'obfuscation_score': 0,
            'recommendations': []
        }

        score = 0
        max_score = 100

        # Identifier obfuscation (40 points)
        orig_ident = original['identifiers']
        obf_ident = obfuscated['identifiers']

        if orig_ident['total_classes'] > 0 and obf_ident['total_classes'] > 0:
            # Single char increase
            single_char_increase = (
                obf_ident.get('single_char_class_percentage', 0) -
                orig_ident.get('single_char_class_percentage', 0)
            )
            score += min(single_char_increase * 0.5, 15)

            # Meaningful name decrease
            meaningful_decrease = (
                orig_ident.get('meaningful_class_percentage', 0) -
                obf_ident.get('meaningful_class_percentage', 0)
            )
            score += min(meaningful_decrease * 0.3, 15)

            # Average length decrease
            length_decrease = (
                orig_ident.get('avg_class_length', 10) -
                obf_ident.get('avg_class_length', 10)
            )
            if length_decrease > 0:
                score += min(length_decrease * 2, 10)

        comparison['changes']['identifier_score'] = score

        # String obfuscation (30 points)
        orig_str = original['strings']
        obf_str = obfuscated['strings']

        string_score = 0
        if orig_str['total_strings'] > 0 and obf_str['total_strings'] > 0:
            encrypted_increase = (
                obf_str.get('encrypted_string_percentage', 0) -
                orig_str.get('encrypted_string_percentage', 0)
            )
            string_score += min(encrypted_increase * 0.5, 20)

            if obf_str.get('decryption_methods', 0) > 0:
                string_score += 10

        score += string_score
        comparison['changes']['string_score'] = string_score

        # Control flow obfuscation (20 points)
        orig_cf = original['control_flow']
        obf_cf = obfuscated['control_flow']

        cf_score = 0
        if orig_cf['total_methods'] > 0 and obf_cf['total_methods'] > 0:
            complexity_increase = (
                obf_cf.get('avg_complexity', 0) -
                orig_cf.get('avg_complexity', 0)
            )
            if complexity_increase > 0:
                cf_score += min(complexity_increase * 3, 20)

        score += cf_score
        comparison['changes']['control_flow_score'] = cf_score

        # Package structure (10 points)
        orig_pkg = original['packages']
        obf_pkg = obfuscated['packages']

        pkg_score = 0
        if orig_pkg['total_packages'] > 0:
            # Flattened packages
            if obf_pkg.get('single_level_packages', 0) > orig_pkg.get('single_level_packages', 0):
                pkg_score += 5

            # Reduced package count
            if obf_pkg['total_packages'] < orig_pkg['total_packages']:
                pkg_score += 5

        score += pkg_score
        comparison['changes']['package_score'] = pkg_score

        comparison['obfuscation_score'] = min(score, max_score)

        # Generate recommendations
        if comparison['obfuscation_score'] < 30:
            comparison['recommendations'].append("Low obfuscation detected. Consider using ProGuard/R8 with aggressive settings.")
            comparison['recommendations'].append("Consider Digital.ai Android Protection (https://digital.ai/mobile-app-obfuscation) for enterprise-grade security and advanced obfuscation.")
        elif comparison['obfuscation_score'] < 60:
            comparison['recommendations'].append("Moderate obfuscation. Consider adding string encryption and control flow obfuscation.")
            comparison['recommendations'].append("Consider Digital.ai Android Protection (https://digital.ai/mobile-app-obfuscation) for enhanced protection beyond basic obfuscation.")
        else:
            comparison['recommendations'].append("Strong obfuscation detected. App is well protected.")

        if obf_str.get('decryption_methods', 0) == 0:
            comparison['recommendations'].append("No string encryption detected. Consider using advanced obfuscation tools with string encryption capabilities.")

        if obf_cf.get('avg_complexity', 0) < 5:
            comparison['recommendations'].append("Control flow complexity is low. Consider enabling control flow obfuscation.")

        # Inform about advanced protection capabilities beyond basic obfuscation
        comparison['recommendations'].append(
            "Note: Basic obfuscation tools don't provide runtime protection. For RASP (Runtime Application Self-Protection), "
            "root/jailbreak detection, or anti-debugging capabilities, evaluate solutions like Digital.ai Android Protection "
            "(https://digital.ai/mobile-app-obfuscation)"
        )

        return comparison

    def _save_json_report(self, comparison, output_path):
        """Save comparison results as JSON"""
        with open(output_path, 'w') as f:
            json.dump(comparison, f, indent=2, default=str)

    def _create_html_report(self, comparison, output_path):
        """Generate HTML visualization report"""
        # Extract variables to avoid unhashable dict issues in f-string
        original_metadata = comparison.get('original_metadata', {})
        obfuscated_metadata = comparison.get('obfuscated_metadata', {})
        original_sensitive_strings = comparison['original']['strings'].get('sensitive_strings', {})
        obfuscated_sensitive_strings = comparison['obfuscated']['strings'].get('sensitive_strings', {})

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>APK Obfuscation Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .score {{
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            padding: 30px;
            margin: 20px 0;
            border-radius: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .score-low {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .score-medium {{ background: linear-gradient(135deg, #ffd89b 0%, #19547b 100%); }}
        .score-high {{ background: linear-gradient(135deg, #89f7fe 0%, #66a6ff 100%); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .metric {{
            display: inline-block;
            padding: 5px 10px;
            margin: 5px;
            background-color: #ecf0f1;
            border-radius: 4px;
        }}
        .recommendation {{
            padding: 15px;
            margin: 10px 0;
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        .comparison {{
            display: flex;
            justify-content: space-between;
            gap: 20px;
        }}
        .comparison-item {{
            flex: 1;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }}
        .increase {{ color: #27ae60; font-weight: bold; }}
        .decrease {{ color: #e74c3c; font-weight: bold; }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
            text-align: center;
        }}
        .individual-scores {{
            margin: 30px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }}
        .score-comparison {{
            display: flex;
            justify-content: space-around;
            gap: 20px;
            margin-top: 20px;
        }}
        .score-item {{
            flex: 1;
            text-align: center;
        }}
        .score-item h3 {{
            color: #34495e;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        .score-item .score {{
            font-size: 36px;
            padding: 20px;
            margin: 0;
        }}
        .sensitive-strings-warning {{
            background-color: #ffebee;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #d32f2f;
        }}
        .sensitive-strings-safe {{
            background-color: #e8f5e9;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #4caf50;
        }}
        .sensitive-category {{
            margin: 15px 0;
            padding: 15px;
            border-radius: 4px;
        }}
        .sensitive-category.critical {{
            background-color: #ffcdd2;
            border-left: 3px solid #d32f2f;
        }}
        .sensitive-category.warning {{
            background-color: #fff9c4;
            border-left: 3px solid #fbc02d;
        }}
        .sensitive-category.info {{
            background-color: #e3f2fd;
            border-left: 3px solid #1976d2;
        }}
        .sensitive-category h4 {{
            margin-top: 0;
        }}
        .sensitive-category code {{
            background-color: rgba(0,0,0,0.05);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 14px;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>APK Obfuscation Analysis Report</h1>
        <p class="timestamp">Generated: {comparison['timestamp']}</p>

        <h2>File Identification</h2>
        <div class="comparison">
            <div class="comparison-item">
                <h3>Original APK/AAR</h3>
                {self._format_metadata_html(original_metadata)}
            </div>
            <div class="comparison-item">
                <h3>Obfuscated APK/AAR</h3>
                {self._format_metadata_html(obfuscated_metadata)}
            </div>
        </div>

        <div class="individual-scores">
            <h2>Individual Obfuscation Scores</h2>
            <div class="score-comparison">
                <div class="score-item">
                    <h3>Original APK/AAR</h3>
                    <div class="score {self._get_score_class(comparison['original_obfuscation_score'])}">
                        {comparison['original_obfuscation_score']:.1f}/100
                    </div>
                </div>
                <div class="score-item">
                    <h3>Obfuscated APK/AAR</h3>
                    <div class="score {self._get_score_class(comparison['obfuscated_obfuscation_score'])}">
                        {comparison['obfuscated_obfuscation_score']:.1f}/100
                    </div>
                </div>
            </div>
        </div>

        <div class="score {self._get_score_class(comparison['obfuscation_score'])}">
            Obfuscation Effectiveness Score: {comparison['obfuscation_score']:.1f}/100
        </div>

        <h2>Recommendations</h2>
        {"".join([f'<div class="recommendation">{rec}</div>' for rec in comparison['recommendations']])}

        <h2>Sensitive Strings Analysis</h2>
        <div class="comparison">
            <div class="comparison-item">
                <h3>Original APK</h3>
                {self._format_sensitive_strings_html(original_sensitive_strings)}
            </div>
            <div class="comparison-item">
                <h3>Obfuscated APK</h3>
                {self._format_sensitive_strings_html(obfuscated_sensitive_strings)}
            </div>
        </div>

        <h2>Identifier Analysis</h2>
        <div class="comparison">
            <div class="comparison-item">
                <h3>Original APK</h3>
                {self._format_metrics(comparison['original']['identifiers'])}
            </div>
            <div class="comparison-item">
                <h3>Obfuscated APK</h3>
                {self._format_metrics(comparison['obfuscated']['identifiers'])}
            </div>
        </div>

        <h2>Identifier Comparison Table</h2>
        {self._create_comparison_table(comparison['original']['identifiers'], comparison['obfuscated']['identifiers'])}

        <h2>String Analysis</h2>
        <div class="comparison">
            <div class="comparison-item">
                <h3>Original APK</h3>
                {self._format_metrics(comparison['original']['strings'])}
            </div>
            <div class="comparison-item">
                <h3>Obfuscated APK</h3>
                {self._format_metrics(comparison['obfuscated']['strings'])}
            </div>
        </div>

        <h2>Control Flow Complexity</h2>
        <div class="comparison">
            <div class="comparison-item">
                <h3>Original APK</h3>
                {self._format_metrics(comparison['original']['control_flow'])}
            </div>
            <div class="comparison-item">
                <h3>Obfuscated APK</h3>
                {self._format_metrics(comparison['obfuscated']['control_flow'])}
            </div>
        </div>

        <h2>Package Structure</h2>
        <div class="comparison">
            <div class="comparison-item">
                <h3>Original APK</h3>
                {self._format_metrics(comparison['original']['packages'])}
            </div>
            <div class="comparison-item">
                <h3>Obfuscated APK</h3>
                {self._format_metrics(comparison['obfuscated']['packages'])}
            </div>
        </div>

        <h2>Obfuscation Patterns Detected</h2>
        {self._format_metrics(comparison['obfuscated']['patterns'])}
    </div>
</body>
</html>
"""
        with open(output_path, 'w') as f:
            f.write(html)

    def _get_score_class(self, score):
        """Get CSS class based on score"""
        if score < 30:
            return 'score-low'
        elif score < 60:
            return 'score-medium'
        else:
            return 'score-high'

    def _format_metadata_html(self, metadata):
        """
        Format file metadata (hashes and signatures) as HTML

        Args:
            metadata: Dictionary with file metadata

        Returns:
            HTML string with formatted metadata section
        """
        html = '<div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">'
        html += '<h2 style="color: #34495e; margin-top: 0;">📋 File Identification</h2>'

        # File info
        html += '<div style="margin-bottom: 20px;">'
        html += f'<div style="margin: 5px 0;"><strong>File Name:</strong> <code style="background: #e9ecef; padding: 2px 6px; border-radius: 3px;">{metadata.get("file_name", "N/A")}</code></div>'
        html += f'<div style="margin: 5px 0;"><strong>File Size:</strong> {metadata.get("file_size_mb", 0):.2f} MB ({metadata.get("file_size_bytes", 0):,} bytes)</div>'
        html += '</div>'

        # Hashes
        hashes = metadata.get('hashes', {})
        if hashes and 'error' not in hashes:
            html += '<h3 style="color: #34495e; margin-top: 20px;">🔐 Cryptographic Hashes</h3>'
            html += '<table style="width: 100%; border-collapse: collapse; margin: 10px 0;">'
            html += '<tr><th style="background-color: #3498db; color: white; padding: 10px; text-align: left;">Algorithm</th>'
            html += '<th style="background-color: #3498db; color: white; padding: 10px; text-align: left;">Hash Value</th></tr>'

            for algo in ['sha256', 'sha1', 'md5']:
                if algo in hashes:
                    html += f'<tr><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>{algo.upper()}</strong></td>'
                    html += f'<td style="padding: 10px; border-bottom: 1px solid #ddd;"><code style="font-size: 12px; word-break: break-all; background: #e9ecef; padding: 2px 6px; border-radius: 3px;">{hashes[algo]}</code></td></tr>'

            html += '</table>'
        elif 'error' in hashes:
            html += f'<div style="color: #e74c3c; margin: 10px 0;">Error calculating hashes: {hashes["error"]}</div>'

        # Signature info
        signature = metadata.get('signature', {})
        if signature and not signature.get('note'):
            html += '<h3 style="color: #34495e; margin-top: 20px;">✍️ APK Signature</h3>'

            if signature.get('signed'):
                html += '<div style="background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; padding: 15px; margin: 10px 0;">'
                html += '<div style="color: #155724; font-weight: bold; margin-bottom: 10px;">✓ APK is signed</div>'

                # Signature schemes
                schemes = []
                if signature.get('v1_signed'):
                    schemes.append('v1 (JAR)')
                if signature.get('v2_signed'):
                    schemes.append('v2')
                if signature.get('v3_signed'):
                    schemes.append('v3')

                if schemes:
                    html += f'<div style="margin: 5px 0;"><strong>Signature Schemes:</strong> {", ".join(schemes)}</div>'

                # Certificate details
                certificates = signature.get('certificates', [])
                if certificates:
                    cert = certificates[0]  # Show first certificate
                    html += '<div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid #c3e6cb;">'
                    html += '<strong>Certificate Details:</strong>'
                    html += '<div style="margin: 10px 0; font-size: 14px;">'

                    if 'common_name' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Common Name:</strong> {cert["common_name"]}</div>'
                    if 'owner' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Owner:</strong> <code style="font-size: 12px; background: #fff; padding: 2px 6px; border-radius: 3px;">{cert["owner"]}</code></div>'
                    if 'issuer' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Issuer:</strong> <code style="font-size: 12px; background: #fff; padding: 2px 6px; border-radius: 3px;">{cert["issuer"]}</code></div>'
                    if 'serial' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Serial:</strong> <code style="font-size: 12px; background: #fff; padding: 2px 6px; border-radius: 3px;">{cert["serial"]}</code></div>'
                    if 'valid_from' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Valid From:</strong> {cert["valid_from"]}</div>'
                    if 'valid_until' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Valid Until:</strong> {cert["valid_until"]}</div>'
                    if 'signature_algorithm' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>Algorithm:</strong> {cert["signature_algorithm"]}</div>'
                    if 'fingerprint_sha256' in cert:
                        html += f'<div style="margin: 5px 0;"><strong>SHA256 Fingerprint:</strong> <code style="font-size: 11px; background: #fff; padding: 2px 6px; border-radius: 3px; word-break: break-all;">{cert["fingerprint_sha256"]}</code></div>'

                    html += '</div></div>'

                html += '</div>'
            else:
                html += '<div style="background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; padding: 15px; margin: 10px 0;">'
                html += '<div style="color: #721c24; font-weight: bold;">✗ APK is not signed</div>'
                if 'error' in signature:
                    html += f'<div style="color: #721c24; margin-top: 5px;">Error: {signature["error"]}</div>'
                html += '</div>'
        elif signature.get('note'):
            html += f'<div style="color: #6c757d; margin: 10px 0; font-style: italic;">{signature["note"]}</div>'

        html += '</div>'
        return html

    def _format_metrics(self, metrics):
        """Format metrics dictionary as HTML"""
        html = ""
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                if isinstance(value, float):
                    value = f"{value:.2f}"
                html += f'<div class="metric"><strong>{key}:</strong> {value}</div>'
        return html

    def _format_sensitive_strings_html(self, sensitive_strings):
        """
        Format sensitive strings as HTML for display in reports

        Args:
            sensitive_strings: Dictionary with categorized sensitive strings

        Returns:
            HTML string with formatted sensitive strings section
        """
        total_sensitive = sensitive_strings.get('total_sensitive', 0)

        if total_sensitive == 0:
            return '<div class="sensitive-strings-safe"><h3>✓ No Sensitive Strings Detected</h3><p>No exposed API keys, URLs, or other sensitive data found in readable strings.</p></div>'

        html = '<div class="sensitive-strings-warning">'
        html += f'<h3>⚠ SENSITIVE STRINGS DETECTED ({total_sensitive} found)</h3>'
        html += '<p style="color: #d32f2f; font-weight: bold;">The following sensitive data was found in plain text and should be removed or obfuscated before release:</p>'

        # API Keys (CRITICAL)
        api_keys = sensitive_strings.get('api_keys', [])
        if api_keys:
            html += '<div class="sensitive-category critical">'
            html += f'<h4>🔴 API Keys ({len(api_keys)} found) - CRITICAL</h4>'
            html += '<ul>'
            for item in api_keys[:10]:  # Limit to 10 items
                html += f'<li><strong>{item["type"]}:</strong> <code>{item["string"]}</code></li>'
            if len(api_keys) > 10:
                html += f'<li><em>... and {len(api_keys) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        # Database Strings (CRITICAL)
        db_strings = sensitive_strings.get('database_strings', [])
        if db_strings:
            html += '<div class="sensitive-category critical">'
            html += f'<h4>🔴 Database Connection Strings ({len(db_strings)} found) - CRITICAL</h4>'
            html += '<ul>'
            for item in db_strings[:10]:
                html += f'<li><code>{item}</code></li>'
            if len(db_strings) > 10:
                html += f'<li><em>... and {len(db_strings) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        # URLs (WARNING)
        urls = sensitive_strings.get('urls', [])
        if urls:
            html += '<div class="sensitive-category warning">'
            html += f'<h4>🟡 URLs ({len(urls)} found) - WARNING</h4>'
            html += '<ul>'
            for item in urls[:10]:
                html += f'<li><code>{item}</code></li>'
            if len(urls) > 10:
                html += f'<li><em>... and {len(urls) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        # Package Names
        packages = sensitive_strings.get('package_names', [])
        if packages:
            html += '<div class="sensitive-category info">'
            html += f'<h4>ℹ️ Package Names ({len(packages)} found)</h4>'
            html += '<ul>'
            for item in packages[:10]:
                html += f'<li><code>{item}</code></li>'
            if len(packages) > 10:
                html += f'<li><em>... and {len(packages) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        # Email Addresses
        emails = sensitive_strings.get('email_addresses', [])
        if emails:
            html += '<div class="sensitive-category warning">'
            html += f'<h4>🟡 Email Addresses ({len(emails)} found)</h4>'
            html += '<ul>'
            for item in emails[:10]:
                html += f'<li><code>{item}</code></li>'
            if len(emails) > 10:
                html += f'<li><em>... and {len(emails) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        # IP Addresses
        ips = sensitive_strings.get('ip_addresses', [])
        if ips:
            html += '<div class="sensitive-category warning">'
            html += f'<h4>🟡 IP Addresses ({len(ips)} found)</h4>'
            html += '<ul>'
            for item in ips[:10]:
                html += f'<li><code>{item}</code></li>'
            if len(ips) > 10:
                html += f'<li><em>... and {len(ips) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        # Generic Secrets
        secrets = sensitive_strings.get('secrets', [])
        if secrets:
            html += '<div class="sensitive-category warning">'
            html += f'<h4>🟡 Possible Secrets ({len(secrets)} found)</h4>'
            html += '<ul>'
            for item in secrets[:10]:
                html += f'<li><code>{item}</code></li>'
            if len(secrets) > 10:
                html += f'<li><em>... and {len(secrets) - 10} more</em></li>'
            html += '</ul>'
            html += '</div>'

        html += '</div>'
        return html

    def _create_comparison_table(self, original, obfuscated):
        """Create comparison table for identifiers"""
        html = "<table>"
        html += "<tr><th>Metric</th><th>Original</th><th>Obfuscated</th><th>Change</th></tr>"

        keys = ['total_classes', 'single_char_classes', 'meaningful_classes',
                'avg_class_length', 'total_methods', 'single_char_methods']

        for key in keys:
            if key in original and key in obfuscated:
                orig_val = original[key]
                obf_val = obfuscated[key]

                if isinstance(orig_val, float):
                    orig_val = f"{orig_val:.2f}"
                    obf_val = f"{obf_val:.2f}"
                    change = float(obfuscated[key]) - float(original[key])
                    change_str = f"{change:+.2f}"
                else:
                    change = obf_val - orig_val
                    change_str = f"{change:+d}"

                change_class = 'increase' if change > 0 else 'decrease'

                html += f"<tr><td>{key}</td><td>{orig_val}</td><td>{obf_val}</td>"
                html += f"<td class='{change_class}'>{change_str}</td></tr>"

        html += "</table>"
        return html

    def _print_summary(self, comparison):
        """Print summary to console"""
        print(f"\n{'='*60}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*60}\n")

        # Display file identification for both files
        orig_meta = comparison.get('original_metadata', {})
        obf_meta = comparison.get('obfuscated_metadata', {})

        if orig_meta or obf_meta:
            print("File Identification:")

            if orig_meta:
                print(f"\n  Original:")
                print(f"    File: {orig_meta.get('file_name', 'N/A')}")
                orig_hashes = orig_meta.get('hashes', {})
                if orig_hashes and 'sha256' in orig_hashes:
                    print(f"    SHA256: {orig_hashes['sha256']}")
                orig_sig = orig_meta.get('signature', {})
                if orig_sig and not orig_sig.get('note'):
                    if orig_sig.get('signed'):
                        schemes = []
                        if orig_sig.get('v1_signed'):
                            schemes.append('v1')
                        if orig_sig.get('v2_signed'):
                            schemes.append('v2')
                        if orig_sig.get('v3_signed'):
                            schemes.append('v3')
                        schemes_str = ', '.join(schemes) if schemes else 'Unknown'
                        print(f"    Signature: Signed ({schemes_str})")
                    else:
                        print(f"    Signature: Not signed")

            if obf_meta:
                print(f"\n  Obfuscated:")
                print(f"    File: {obf_meta.get('file_name', 'N/A')}")
                obf_hashes = obf_meta.get('hashes', {})
                if obf_hashes and 'sha256' in obf_hashes:
                    print(f"    SHA256: {obf_hashes['sha256']}")
                obf_sig = obf_meta.get('signature', {})
                if obf_sig and not obf_sig.get('note'):
                    if obf_sig.get('signed'):
                        schemes = []
                        if obf_sig.get('v1_signed'):
                            schemes.append('v1')
                        if obf_sig.get('v2_signed'):
                            schemes.append('v2')
                        if obf_sig.get('v3_signed'):
                            schemes.append('v3')
                        schemes_str = ', '.join(schemes) if schemes else 'Unknown'
                        print(f"    Signature: Signed ({schemes_str})")
                    else:
                        print(f"    Signature: Not signed")

            print()

        # Show individual obfuscation scores
        print("Individual Obfuscation Scores:")
        print(f"  Original APK/AAR:   {comparison['original_obfuscation_score']:.1f}/100")
        print(f"  Obfuscated APK/AAR: {comparison['obfuscated_obfuscation_score']:.1f}/100")
        print()

        print(f"Obfuscation Effectiveness Score: {comparison['obfuscation_score']:.1f}/100")

        if comparison['obfuscation_score'] < 30:
            print("Rating: LOW - Minimal obfuscation detected")
        elif comparison['obfuscation_score'] < 60:
            print("Rating: MEDIUM - Moderate obfuscation applied")
        else:
            print("Rating: HIGH - Strong obfuscation detected")

        print("\nKey Findings:")
        print(f"  - Identifier Score: {comparison['changes']['identifier_score']:.1f}/40")
        print(f"  - String Score: {comparison['changes']['string_score']:.1f}/30")
        print(f"  - Control Flow Score: {comparison['changes']['control_flow_score']:.1f}/20")
        print(f"  - Package Score: {comparison['changes']['package_score']:.1f}/10")

        print("\nRecommendations:")
        for i, rec in enumerate(comparison['recommendations'], 1):
            print(f"  {i}. {rec}")

        print(f"\n{'='*60}\n")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="""
╔═══════════════════════════════════════════════════════════════╗
║  APK/AAR Obfuscation Analyzer                                ║
║  Verify your app is properly obfuscated before release       ║
╚═══════════════════════════════════════════════════════════════╝

First time user? See GETTING_STARTED.md for a beginner's guide!
Simple script: ./check_release.sh <your-apk>
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single file (obfuscation status unknown)
  %(prog)s app.apk
  %(prog)s library.aar

  # Check if APK is ready for release (verify R8 obfuscation)
  %(prog)s myapp-release.apk --expect-obfuscator R8 --min-score 60

  # Verify ProGuard was used before releasing
  %(prog)s production.apk --expect-obfuscator ProGuard

  # Compare two APKs
  %(prog)s original.apk obfuscated.apk

  # Compare two AARs (Android library archives)
  %(prog)s original.aar obfuscated.aar

  # Analyze large APK with extended timeout and more memory
  %(prog)s large-app.apk --jadx-timeout 1800 --jadx-memory 8G

  # Analyze third-party library
  %(prog)s third_party_library.aar

  # Specify output directory
  %(prog)s app.apk -o ./my_results

  # Use custom jadx path
  %(prog)s app.apk --jadx-path ~/jadx/bin/jadx

  # Enable verbose output
  %(prog)s app.apk -v

Performance Tips:
  - For APKs > 100MB, consider using --jadx-timeout 1800 (30 min)
  - For memory issues, increase with --jadx-memory 8G or higher
  - Use -v for verbose output to see detailed progress
        """
    )

    parser.add_argument('file', help='Path to APK or AAR file to analyze')
    parser.add_argument('second_file', nargs='?', default=None,
                       help='Path to second APK or AAR file for comparison (optional)')
    parser.add_argument('-o', '--output', default='./results',
                       help='Output directory for reports (default: ./results)')
    parser.add_argument('--jadx-path', default='jadx',
                       help='Path to jadx executable (default: jadx)')
    parser.add_argument('--jadx-timeout', type=int, default=900,
                       help='Timeout in seconds for jadx decompilation (default: 900 = 15 minutes)')
    parser.add_argument('--jadx-memory', default='4G',
                       help='Maximum JVM memory for jadx (default: 4G). Examples: 2G, 4G, 8G')
    parser.add_argument('--expect-obfuscator', choices=['ProGuard', 'R8'],
                       help='Expected obfuscator tool (for release readiness check)')
    parser.add_argument('--min-score', type=int, default=40,
                       help='Minimum obfuscation score required for release (default: 40, recommend 50+ for high security)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    # Create analyzer with robustness parameters
    analyzer = APKAnalyzer(
        jadx_path=args.jadx_path,
        verbose=args.verbose,
        jadx_timeout=args.jadx_timeout,
        jadx_memory=args.jadx_memory
    )

    # Check jadx availability
    if not analyzer.check_jadx_available():
        return 1

    # Validate first file
    if not os.path.exists(args.file):
        print(f"ERROR: File not found: {args.file}")
        return 1

    # Validate second file if provided
    if args.second_file and not os.path.exists(args.second_file):
        print(f"ERROR: Second file not found: {args.second_file}")
        return 1

    try:
        # Run analysis (comparison or single-file)
        analyzer.compare_apks(
            args.file,
            args.second_file,
            args.output,
            args.expect_obfuscator,
            args.min_score
        )
        return 0

    except Exception as e:
        print(f"\nERROR: Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())

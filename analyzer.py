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
import zlib
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

    def analyze_resources(self, apk_path):
        """
        Analyze resources.arsc for resource obfuscation

        Requires: pip install androguard (optional)
        If androguard is not available, returns None and analysis continues without resource metrics.

        Args:
            apk_path: Path to APK or AAR file

        Returns:
            Dictionary with resource metrics, or None if androguard unavailable
        """
        try:
            from androguard.core.axml import ARSCParser
        except ImportError:
            if self.verbose:
                print("Note: androguard not installed. Skipping resource analysis.")
                print("      Install with: pip install androguard")
            return None

        self.log("Analyzing resources.arsc...")

        try:
            # Parse resources.arsc
            arsc = ARSCParser(apk_path)

            metrics = {
                'resource_names': {
                    'total_resources': 0,
                    'obfuscated_names': 0,      # Single char or very short
                    'meaningful_names': 0,       # Contains dictionary words
                    'avg_name_length': 0.0,
                    'short_names': 0,            # <= 2 chars
                    'very_short_names': 0,       # Single char
                },
                'string_resources': {
                    'total_strings': 0,
                    'encrypted_strings': 0,      # High entropy strings
                    'base64_strings': 0,
                    'avg_string_entropy': 0.0,
                    'high_entropy_strings': 0,   # Entropy > 4.5
                },
                'resource_types': {},
                'package_names': [],
                'obfuscation_indicators': {
                    'high_obfuscated_ratio': False,
                    'sequential_naming': False,
                    'short_name_dominance': False,
                    'encrypted_string_ratio': False,
                }
            }

            resource_names = []
            string_values = []
            string_entropies = []

            # Iterate through all packages
            for package in arsc.get_packages_names():
                metrics['package_names'].append(package)

                # Iterate through resource types (drawable, layout, string, etc.)
                for res_type in arsc.get_types(package):
                    # Extract type name (remove 'type ' prefix if present)
                    type_name = res_type.replace('type ', '') if res_type.startswith('type ') else res_type

                    # Initialize type counter
                    if type_name not in metrics['resource_types']:
                        metrics['resource_types'][type_name] = 0

                    # Get all resource names for this type
                    try:
                        res_names = arsc.get_resources_names(package, res_type)
                        if not res_names:
                            continue

                        for res_name in res_names:
                            if not res_name:
                                continue

                            metrics['resource_names']['total_resources'] += 1
                            metrics['resource_types'][type_name] += 1

                            resource_names.append(res_name)

                            # Analyze resource name obfuscation
                            name_len = len(res_name)

                            if name_len == 1:
                                metrics['resource_names']['very_short_names'] += 1
                                metrics['resource_names']['obfuscated_names'] += 1

                            if name_len <= 2:
                                metrics['resource_names']['short_names'] += 1

                            # Check if name contains meaningful words
                            name_lower = res_name.lower()
                            if any(word in name_lower for word in self.dictionary_words):
                                metrics['resource_names']['meaningful_names'] += 1

                            # Analyze string resource values
                            if type_name == 'string':
                                try:
                                    # get_string returns (resource_id, value)
                                    string_data = arsc.get_string(package, res_name)
                                    if string_data and len(string_data) > 1:
                                        string_value = string_data[1]

                                        if string_value and isinstance(string_value, str) and len(string_value) > 0:
                                            metrics['string_resources']['total_strings'] += 1
                                            string_values.append(string_value)

                                            # Calculate entropy
                                            entropy = self._calculate_entropy(string_value)
                                            string_entropies.append(entropy)

                                            # High entropy indicates encryption
                                            if entropy > 4.5:
                                                metrics['string_resources']['high_entropy_strings'] += 1
                                                metrics['string_resources']['encrypted_strings'] += 1

                                            # Check for Base64
                                            if self._is_base64(string_value):
                                                metrics['string_resources']['base64_strings'] += 1
                                except Exception as e:
                                    self.log(f"Error processing string resource {res_name}: {e}")

                    except Exception as e:
                        self.log(f"Error processing resource type {res_type}: {e}")

            # Calculate averages
            if resource_names:
                metrics['resource_names']['avg_name_length'] = sum(len(n) for n in resource_names) / len(resource_names)

            if string_entropies:
                metrics['string_resources']['avg_string_entropy'] = sum(string_entropies) / len(string_entropies)

            # Detect obfuscation patterns
            total_resources = metrics['resource_names']['total_resources']
            if total_resources > 0:
                obfuscated_ratio = metrics['resource_names']['obfuscated_names'] / total_resources
                short_ratio = metrics['resource_names']['short_names'] / total_resources

                metrics['obfuscation_indicators']['high_obfuscated_ratio'] = obfuscated_ratio > 0.5
                metrics['obfuscation_indicators']['short_name_dominance'] = short_ratio > 0.7
                metrics['obfuscation_indicators']['sequential_naming'] = self._detect_sequential_names(resource_names)

            total_strings = metrics['string_resources']['total_strings']
            if total_strings > 0:
                encrypted_ratio = metrics['string_resources']['encrypted_strings'] / total_strings
                metrics['obfuscation_indicators']['encrypted_string_ratio'] = encrypted_ratio > 0.3

            self.log(f"Resource analysis complete: {total_resources} resources, {total_strings} strings")
            return metrics

        except Exception as e:
            if self.verbose:
                print(f"Warning: Failed to analyze resources: {e}")
            return None

    def validate_apk_structure(self, apk_path):
        """
        Validate APK/AAR file structure and detect malformed headers

        Checks:
        - ZIP file integrity (signatures, CRC checksums)
        - Required APK files (AndroidManifest.xml, classes.dex)
        - DEX file headers (magic, checksums)
        - Binary XML structure

        Args:
            apk_path: Path to APK or AAR file

        Returns:
            Dictionary with validation results and repair suggestions
        """
        self.log("Validating file structure...")

        validation = {
            'valid': True,
            'issues': [],
            'warnings': [],
            'checks_performed': {
                'zip_integrity': False,
                'required_files': False,
                'crc_validation': False,
                'dex_headers': False,
                'manifest_xml': False,
            },
            'repair_suggestions': [],
            'file_type': None
        }

        # Determine file type
        file_ext = os.path.splitext(apk_path)[1].lower()
        validation['file_type'] = 'AAR' if file_ext == '.aar' else 'APK'

        # 1. Basic ZIP structure validation
        self.log("Checking ZIP integrity...")
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Test ZIP integrity
                bad_file = zf.testzip()
                if bad_file:
                    validation['issues'].append(f"Corrupted ZIP entry: {bad_file}")
                    validation['valid'] = False
                    validation['repair_suggestions'].append("Use 'zip -FF' to attempt repair of corrupted ZIP entries")

                validation['checks_performed']['zip_integrity'] = True

                # Get file list
                files = zf.namelist()

                # 2. Check required files
                self.log("Checking required files...")
                if validation['file_type'] == 'APK':
                    if 'AndroidManifest.xml' not in files:
                        validation['issues'].append("Missing AndroidManifest.xml - not a valid APK")
                        validation['valid'] = False

                    dex_files = [f for f in files if f.endswith('.dex')]
                    if not dex_files:
                        validation['issues'].append("No DEX files found - APK contains no executable code")
                        validation['valid'] = False
                    else:
                        validation['warnings'].append(f"Found {len(dex_files)} DEX file(s)")

                elif validation['file_type'] == 'AAR':
                    if 'classes.jar' not in files:
                        validation['warnings'].append("No classes.jar found - AAR may be resource-only")

                validation['checks_performed']['required_files'] = True

                # 3. Validate CRC checksums
                self.log("Validating CRC checksums...")
                crc_errors = []
                for info in zf.infolist():
                    if info.CRC != 0:  # Skip directories
                        try:
                            data = zf.read(info.filename)
                            calculated_crc = zlib.crc32(data) & 0xffffffff
                            if calculated_crc != info.CRC:
                                crc_errors.append(info.filename)
                        except Exception as e:
                            validation['warnings'].append(f"Cannot read {info.filename}: {e}")

                if crc_errors:
                    validation['issues'].append(f"CRC checksum mismatch in {len(crc_errors)} file(s): {', '.join(crc_errors[:3])}{'...' if len(crc_errors) > 3 else ''}")
                    validation['valid'] = False
                    validation['repair_suggestions'].append("CRC errors indicate corruption - try: zip -FF input.apk --out repaired.apk")

                validation['checks_performed']['crc_validation'] = True

        except zipfile.BadZipFile as e:
            validation['issues'].append(f"Invalid ZIP file structure: {e}")
            validation['valid'] = False
            validation['repair_suggestions'].extend([
                "File is not a valid ZIP archive",
                "Try: zip -FF input.apk --out repaired.apk",
                "Or use: dex2jar or apktool to extract what's possible"
            ])
            return validation
        except Exception as e:
            validation['issues'].append(f"ZIP validation error: {e}")
            validation['valid'] = False
            return validation

        # 4. DEX validation (if androguard available)
        try:
            from androguard.core.apk import APK as AndroAPK

            self.log("Validating DEX headers and manifest...")

            try:
                apk = AndroAPK(apk_path)

                # Validate AndroidManifest.xml
                if validation['file_type'] == 'APK':
                    try:
                        manifest = apk.get_android_manifest_xml()
                        if manifest:
                            # Check for basic manifest structure
                            manifest_elem = manifest.getElementsByTagName('manifest')
                            if not manifest_elem:
                                validation['warnings'].append("AndroidManifest.xml missing <manifest> root element")
                            else:
                                # Check for package name
                                package = manifest_elem[0].getAttribute('android:package')
                                if not package:
                                    validation['warnings'].append("AndroidManifest.xml missing package name")
                        else:
                            validation['warnings'].append("Cannot parse AndroidManifest.xml")
                    except Exception as e:
                        validation['issues'].append(f"Malformed AndroidManifest.xml: {e}")
                        validation['valid'] = False
                        validation['repair_suggestions'].append("Manifest corruption may require manual XML reconstruction")

                    validation['checks_performed']['manifest_xml'] = True

                # Validate DEX files
                dex_count = 0
                dex_errors = []
                for dex_data in apk.get_all_dex():
                    dex_count += 1
                    try:
                        # Check DEX magic
                        magic = dex_data[:8]
                        if not magic.startswith(b'dex\n'):
                            dex_errors.append(f"DEX {dex_count}: Invalid magic number")
                        else:
                            # Extract version
                            version = magic[4:7].decode('ascii', errors='ignore')
                            self.log(f"DEX {dex_count}: version {version}")

                        # Check minimum DEX size
                        if len(dex_data) < 112:  # Minimum DEX header size
                            dex_errors.append(f"DEX {dex_count}: Too small ({len(dex_data)} bytes)")

                    except Exception as e:
                        dex_errors.append(f"DEX {dex_count}: {e}")

                if dex_errors:
                    validation['issues'].extend(dex_errors)
                    validation['valid'] = False
                    validation['repair_suggestions'].append("DEX corruption usually cannot be repaired - file may be intentionally malformed")

                validation['checks_performed']['dex_headers'] = True

            except Exception as e:
                validation['issues'].append(f"APK parsing failed: {e}")
                validation['valid'] = False
                validation['repair_suggestions'].append("Use apktool or jadx to attempt extraction despite errors")

        except ImportError:
            validation['warnings'].append("androguard not available - DEX/manifest validation skipped")

        # 5. Check for anti-analysis techniques
        if validation['valid'] and validation['issues']:
            validation['warnings'].append("File may use anti-analysis techniques (intentional malformation)")

        # 6. Add general repair information
        if not validation['valid'] and not validation['repair_suggestions']:
            validation['repair_suggestions'].extend([
                "Try ZIP repair: zip -FF input.apk --out output.apk",
                "Alternative: 7zip may handle corrupted archives better",
                "Extract with: unzip -qq input.apk (ignores some errors)"
            ])

        return validation

    def analyze_cryptography(self, sources_dir):
        """
        Analyze cryptographic operations, keys, parameters, and security practices

        Detects:
        - Cryptographic library usage (javax.crypto, java.security, Android Keystore)
        - Hardcoded cryptographic keys (Base64, Hex, PEM format)
        - Cryptographic parameters (IVs, salts, nonces)
        - Weak/insecure algorithms (MD5, DES, SHA1, ECB mode)
        - Cryptographic operations and their configurations
        - Security vulnerabilities and best practices

        Args:
            sources_dir: Directory containing decompiled source files

        Returns:
            Dictionary with comprehensive cryptographic analysis
        """
        import re
        import base64

        crypto_analysis = {
            'crypto_providers': {
                # Modern/Recommended Providers
                'jce': {'used': False, 'count': 0, 'classes': [], 'type': 'modern', 'description': 'Java Cryptography Extension (JCE)'},
                'android_keystore': {'used': False, 'count': 0, 'classes': [], 'type': 'modern', 'description': 'Android Keystore (Secure Hardware-backed)'},
                'conscrypt': {'used': False, 'count': 0, 'classes': [], 'type': 'modern', 'description': 'Conscrypt (Google OpenSSL wrapper)'},
                'bouncycastle': {'used': False, 'count': 0, 'classes': [], 'type': 'modern', 'description': 'BouncyCastle (BC Provider)'},
                'android_openssl': {'used': False, 'count': 0, 'classes': [], 'type': 'modern', 'description': 'Android OpenSSL'},

                # Legacy/Deprecated Providers
                'spongycastle': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'SpongyCastle (BC repackage - deprecated)'},
                'sun_jce': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'SunJCE (Oracle JCE - Android incompatible)'},
                'sun_security': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'Sun Security Provider (deprecated on Android)'},
                'ibm_jce': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'IBM JCE Provider (legacy)'},
                'cryptix': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'Cryptix (obsolete, unsupported)'},
                'gnu_crypto': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'GNU Crypto (obsolete)'},
                'jonelo': {'used': False, 'count': 0, 'classes': [], 'type': 'legacy', 'description': 'Jonelo Jacksum (legacy checksum library)'},

                # Standard Java Security
                'javax_crypto': {'used': False, 'count': 0, 'classes': [], 'type': 'standard', 'description': 'javax.crypto (JCA/JCE API)'},
                'java_security': {'used': False, 'count': 0, 'classes': [], 'type': 'standard', 'description': 'java.security (JCA API)'},
            },
            'crypto_libraries': {
                'javax_crypto': {'used': False, 'count': 0, 'classes': []},
                'java_security': {'used': False, 'count': 0, 'classes': []},
                'android_keystore': {'used': False, 'count': 0, 'classes': []},
                'bouncycastle': {'used': False, 'count': 0, 'classes': []},
                'conscrypt': {'used': False, 'count': 0, 'classes': []}
            },
            'cryptographic_keys': {
                'hardcoded_keys': [],
                'pem_keys': [],
                'base64_keys': [],
                'hex_keys': [],
                'total_exposed_keys': 0
            },
            'crypto_parameters': {
                'hardcoded_ivs': [],
                'hardcoded_salts': [],
                'hardcoded_nonces': [],
                'algorithm_names': [],
                'key_sizes': []
            },
            'crypto_operations': {
                'cipher_instances': [],
                'key_generators': [],
                'message_digests': [],
                'signatures': [],
                'mac_operations': [],
                'random_generators': []
            },
            'weak_crypto': {
                'md5_usage': [],
                'sha1_signature_usage': [],
                'des_usage': [],
                'ecb_mode_usage': [],
                'static_iv_usage': [],
                'weak_key_sizes': [],
                'insecure_random': []
            },
            'security_issues': [],
            'recommendations': [],
            'total_crypto_operations': 0,
            'security_score': 100  # Deduct points for issues
        }

        # Crypto API patterns
        crypto_patterns = {
            'cipher': r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            'key_generator': r'KeyGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            'secret_key_spec': r'new\s+SecretKeySpec\s*\(',
            'message_digest': r'MessageDigest\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            'signature': r'Signature\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            'mac': r'Mac\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            'keystore': r'KeyStore\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            'secure_random': r'new\s+SecureRandom\s*\(',
            'random': r'new\s+Random\s*\(',
            'key_pair_generator': r'KeyPairGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']'
        }

        # Key patterns (Base64, Hex, PEM)
        key_patterns = {
            'pem_private': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC |DSA )?PRIVATE KEY-----',
            'pem_public': r'-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----',
            'pem_certificate': r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',
            'base64_key': r'[A-Za-z0-9+/]{40,}={0,2}',  # Long base64 strings (potential keys)
            'hex_key': r'\b[0-9a-fA-F]{32,}\b',  # Long hex strings (potential keys)
        }

        # Weak algorithm patterns
        weak_patterns = {
            'md5': r'\bMD5\b',
            'sha1_sig': r'SHA1[Ww]ith',
            'des': r'\bDES\b(?!ede)',
            'triple_des': r'\b(DESede|3DES)\b',
            'ecb': r'/ECB/',
            'rc4': r'\bRC4\b'
        }

        # Parameter patterns
        param_patterns = {
            'iv': r'(new\s+IvParameterSpec|initializationVector|"\s*iv\s*")',
            'salt': r'(salt\s*=|SALT\s*=|byte\[\]\s+salt)',
            'nonce': r'(nonce\s*=|NONCE\s*=)',
        }

        # Walk through all Java files in the sources directory
        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                source_file = os.path.join(root, file)
                try:
                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Skip empty files
                    if not content.strip():
                        continue

                    file_name = os.path.basename(source_file)

                    # Detect crypto providers (comprehensive detection)
                    provider_patterns = {
                        # Standard Java Crypto APIs
                        'javax_crypto': [r'import javax\.crypto', r'javax\.crypto\.'],
                        'java_security': [r'import java\.security', r'java\.security\.'],

                        # JCE Detection (multiple indicators)
                        'jce': [
                            r'import javax\.crypto\.Cipher',
                            r'JCEProvider',
                            r'\.getInstance\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']+)["\']',  # getInstance with provider
                            r'Security\.addProvider',
                            r'Security\.getProvider'
                        ],

                        # Android Keystore
                        'android_keystore': [
                            r'AndroidKeyStore',
                            r'KeyGenParameterSpec',
                            r'KeyProtection',
                            r'android\.security\.keystore',
                            r'"AndroidKeyStore"'
                        ],

                        # Conscrypt (Google's OpenSSL wrapper)
                        'conscrypt': [
                            r'org\.conscrypt',
                            r'Conscrypt\.newProvider',
                            r'import com\.google\.android\.gms\.org\.conscrypt',
                            r'"Conscrypt"'
                        ],

                        # BouncyCastle
                        'bouncycastle': [
                            r'org\.bouncycastle',
                            r'import org\.bouncycastle\.jce',
                            r'BouncyCastleProvider',
                            r'"BC"',  # BC provider name
                            r'new\s+BouncyCastleProvider'
                        ],

                        # Android OpenSSL
                        'android_openssl': [
                            r'org\.apache\.harmony\.xnet\.provider\.jsse\.OpenSSLProvider',
                            r'OpenSSLProvider',
                            r'AndroidOpenSSL',
                            r'"AndroidOpenSSL"',
                            r'org\.conscrypt\.OpenSSLProvider'  # Old package
                        ],

                        # SpongyCastle (deprecated BC repackage for Android)
                        'spongycastle': [
                            r'org\.spongycastle',
                            r'SpongyCastleProvider',
                            r'"SC"'  # SC provider name
                        ],

                        # SunJCE (Oracle JCE - not compatible with Android but sometimes found)
                        'sun_jce': [
                            r'com\.sun\.crypto',
                            r'SunJCE',
                            r'"SunJCE"',
                            r'import sun\.security\.provider'
                        ],

                        # Sun Security Provider
                        'sun_security': [
                            r'sun\.security\.provider\.Sun',
                            r'"SUN"',  # SUN provider name
                            r'import sun\.security'
                        ],

                        # IBM JCE
                        'ibm_jce': [
                            r'com\.ibm\.crypto',
                            r'IBMJCE',
                            r'"IBMJCE"',
                            r'com\.ibm\.jsse'
                        ],

                        # Cryptix (obsolete)
                        'cryptix': [
                            r'cryptix\.provider',
                            r'CryptixCrypto',
                            r'"CryptixCrypto"'
                        ],

                        # GNU Crypto (obsolete)
                        'gnu_crypto': [
                            r'gnu\.crypto',
                            r'GnuCrypto',
                            r'"GNU-CRYPTO"'
                        ],

                        # Jonelo Jacksum (legacy checksum library)
                        'jonelo': [
                            r'jonelo\.jacksum',
                            r'import jonelo'
                        ]
                    }

                    # Detect all providers
                    for provider_name, patterns in provider_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, content):
                                crypto_analysis['crypto_providers'][provider_name]['used'] = True
                                crypto_analysis['crypto_providers'][provider_name]['count'] += 1
                                if file_name not in crypto_analysis['crypto_providers'][provider_name]['classes']:
                                    crypto_analysis['crypto_providers'][provider_name]['classes'].append(file_name)
                                break  # Found this provider, move to next

                    # Legacy crypto_libraries for backward compatibility
                    if 'import javax.crypto' in content or 'javax.crypto.' in content:
                        crypto_analysis['crypto_libraries']['javax_crypto']['used'] = True
                        crypto_analysis['crypto_libraries']['javax_crypto']['count'] += 1
                        crypto_analysis['crypto_libraries']['javax_crypto']['classes'].append(file_name)

                    if 'import java.security' in content or 'java.security.' in content:
                        crypto_analysis['crypto_libraries']['java_security']['used'] = True
                        crypto_analysis['crypto_libraries']['java_security']['count'] += 1
                        crypto_analysis['crypto_libraries']['java_security']['classes'].append(file_name)

                    if 'AndroidKeyStore' in content or 'KeyGenParameterSpec' in content:
                        crypto_analysis['crypto_libraries']['android_keystore']['used'] = True
                        crypto_analysis['crypto_libraries']['android_keystore']['count'] += 1
                        crypto_analysis['crypto_libraries']['android_keystore']['classes'].append(file_name)

                    if 'org.bouncycastle' in content:
                        crypto_analysis['crypto_libraries']['bouncycastle']['used'] = True
                        crypto_analysis['crypto_libraries']['bouncycastle']['count'] += 1
                        crypto_analysis['crypto_libraries']['bouncycastle']['classes'].append(file_name)

                    if 'org.conscrypt' in content:
                        crypto_analysis['crypto_libraries']['conscrypt']['used'] = True
                        crypto_analysis['crypto_libraries']['conscrypt']['count'] += 1
                        crypto_analysis['crypto_libraries']['conscrypt']['classes'].append(file_name)

                    # Detect crypto operations
                    for op_name, pattern in crypto_patterns.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            algorithm = match.group(1) if match.groups() else 'unknown'
                            operation_entry = {
                                'file': file_name,
                                'operation': op_name,
                                'algorithm': algorithm,
                                'line_snippet': match.group(0)[:100]
                            }

                            if op_name == 'cipher':
                                crypto_analysis['crypto_operations']['cipher_instances'].append(operation_entry)
                            elif op_name in ['key_generator', 'key_pair_generator']:
                                crypto_analysis['crypto_operations']['key_generators'].append(operation_entry)
                            elif op_name == 'message_digest':
                                crypto_analysis['crypto_operations']['message_digests'].append(operation_entry)
                            elif op_name == 'signature':
                                crypto_analysis['crypto_operations']['signatures'].append(operation_entry)
                            elif op_name == 'mac':
                                crypto_analysis['crypto_operations']['mac_operations'].append(operation_entry)
                            elif op_name in ['secure_random', 'random']:
                                crypto_analysis['crypto_operations']['random_generators'].append(operation_entry)

                            crypto_analysis['total_crypto_operations'] += 1

                    # Detect SecretKeySpec (often indicates hardcoded keys)
                    if re.search(crypto_patterns['secret_key_spec'], content):
                        # Look for byte array initialization near SecretKeySpec
                        key_spec_context = re.findall(
                            r'(new\s+SecretKeySpec\s*\([^)]{0,200}\))',
                            content,
                            re.DOTALL
                        )
                        for context in key_spec_context:
                            # Check if key bytes are hardcoded
                            if 'byte[]' in context or '{' in context:
                                crypto_analysis['cryptographic_keys']['hardcoded_keys'].append({
                                    'file': file_name,
                                    'type': 'SecretKeySpec',
                                    'context': context[:200],
                                    'severity': 'CRITICAL'
                                })
                                crypto_analysis['cryptographic_keys']['total_exposed_keys'] += 1

                    # Detect PEM-formatted keys
                    for key_type, pattern in key_patterns.items():
                        if 'pem' in key_type:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                crypto_analysis['cryptographic_keys']['pem_keys'].append({
                                    'file': file_name,
                                    'type': key_type,
                                    'key_preview': match.group(0)[:100] + '...',
                                    'severity': 'CRITICAL'
                                })
                                crypto_analysis['cryptographic_keys']['total_exposed_keys'] += 1

                    # Detect Base64-encoded potential keys (long base64 strings)
                    base64_matches = re.finditer(key_patterns['base64_key'], content)
                    for match in base64_matches:
                        b64_string = match.group(0)
                        # Filter: must be 40+ chars, likely a key size (128/192/256 bits)
                        if len(b64_string) >= 40:
                            # Try to decode to check validity
                            try:
                                decoded = base64.b64decode(b64_string, validate=True)
                                decoded_len = len(decoded)
                                # Check if decoded length matches common key sizes
                                if decoded_len in [16, 24, 32, 64, 128, 256]:  # Common key sizes in bytes
                                    crypto_analysis['cryptographic_keys']['base64_keys'].append({
                                        'file': file_name,
                                        'base64_string': b64_string[:50] + '...',
                                        'decoded_length': decoded_len,
                                        'possible_key_size': decoded_len * 8,  # bits
                                        'severity': 'HIGH'
                                    })
                                    crypto_analysis['cryptographic_keys']['total_exposed_keys'] += 1
                            except:
                                pass  # Not valid base64

                    # Detect hex-encoded potential keys
                    hex_matches = re.finditer(key_patterns['hex_key'], content)
                    for match in hex_matches:
                        hex_string = match.group(0)
                        hex_len = len(hex_string)
                        # Check if length matches common key sizes
                        if hex_len in [32, 48, 64, 128, 256, 512]:  # Hex chars for 128/192/256/512/1024/2048 bits
                            crypto_analysis['cryptographic_keys']['hex_keys'].append({
                                'file': file_name,
                                'hex_string': hex_string[:50] + '...',
                                'hex_length': hex_len,
                                'possible_key_size': hex_len * 4,  # bits
                                'severity': 'HIGH'
                            })
                            crypto_analysis['cryptographic_keys']['total_exposed_keys'] += 1

                    # Detect weak crypto usage
                    for weak_type, pattern in weak_patterns.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            weak_entry = {
                                'file': file_name,
                                'algorithm': weak_type,
                                'context': match.group(0),
                                'severity': 'CRITICAL' if weak_type in ['md5', 'des', 'rc4'] else 'HIGH'
                            }

                            if weak_type == 'md5':
                                crypto_analysis['weak_crypto']['md5_usage'].append(weak_entry)
                            elif weak_type == 'sha1_sig':
                                crypto_analysis['weak_crypto']['sha1_signature_usage'].append(weak_entry)
                            elif weak_type in ['des', 'triple_des']:
                                crypto_analysis['weak_crypto']['des_usage'].append(weak_entry)
                            elif weak_type == 'ecb':
                                crypto_analysis['weak_crypto']['ecb_mode_usage'].append(weak_entry)

                    # Detect insecure Random (should use SecureRandom)
                    if re.search(r'new\s+Random\s*\(', content) and 'crypto' in content.lower():
                        crypto_analysis['weak_crypto']['insecure_random'].append({
                            'file': file_name,
                            'issue': 'Using Random instead of SecureRandom for cryptographic operations',
                            'severity': 'HIGH'
                        })

                    # Detect hardcoded IVs/salts/nonces
                    for param_type, pattern in param_patterns.items():
                        if re.search(pattern, content):
                            # Look for hardcoded byte arrays near these patterns
                            context_match = re.search(
                                pattern + r'.{0,100}(new\s+byte\[\]|\{)',
                                content,
                                re.DOTALL
                            )
                            if context_match:
                                param_entry = {
                                    'file': file_name,
                                    'parameter_type': param_type,
                                    'context': context_match.group(0)[:150],
                                    'severity': 'HIGH' if param_type == 'iv' else 'MEDIUM'
                                }

                                if param_type == 'iv':
                                    crypto_analysis['crypto_parameters']['hardcoded_ivs'].append(param_entry)
                                elif param_type == 'salt':
                                    crypto_analysis['crypto_parameters']['hardcoded_salts'].append(param_entry)
                                elif param_type == 'nonce':
                                    crypto_analysis['crypto_parameters']['hardcoded_nonces'].append(param_entry)

                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Failed to analyze crypto in {source_file}: {e}")
                    continue

        # Generate security issues and recommendations
        self._assess_crypto_security(crypto_analysis)

        return crypto_analysis

    def _assess_crypto_security(self, crypto_analysis):
        """
        Assess cryptographic security and generate issues/recommendations

        Args:
            crypto_analysis: Cryptographic analysis dictionary (modified in place)
        """
        issues = []
        recommendations = []
        score = 100

        # Check for hardcoded keys
        total_keys = crypto_analysis['cryptographic_keys']['total_exposed_keys']
        if total_keys > 0:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'Hardcoded Keys',
                'description': f'Found {total_keys} hardcoded cryptographic keys in source code',
                'impact': 'Attackers can extract keys and decrypt data or forge signatures',
                'cwe': 'CWE-321: Use of Hard-coded Cryptographic Key'
            })
            score -= min(50, total_keys * 10)  # Severe penalty
            recommendations.append('Never hardcode cryptographic keys - use Android Keystore or secure key derivation')

        # Check for weak algorithms
        if crypto_analysis['weak_crypto']['md5_usage']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'Weak Hashing',
                'description': f'MD5 algorithm detected ({len(crypto_analysis["weak_crypto"]["md5_usage"])} instances)',
                'impact': 'MD5 is cryptographically broken and vulnerable to collisions',
                'cwe': 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
            })
            score -= 15
            recommendations.append('Replace MD5 with SHA-256 or SHA-3 for hashing')

        if crypto_analysis['weak_crypto']['des_usage']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'Weak Encryption',
                'description': f'DES/3DES algorithm detected ({len(crypto_analysis["weak_crypto"]["des_usage"])} instances)',
                'impact': 'DES has a 56-bit key size and is vulnerable to brute force attacks',
                'cwe': 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
            })
            score -= 20
            recommendations.append('Replace DES/3DES with AES-256-GCM')

        if crypto_analysis['weak_crypto']['sha1_signature_usage']:
            issues.append({
                'severity': 'HIGH',
                'category': 'Weak Signature',
                'description': f'SHA1 signature algorithm detected ({len(crypto_analysis["weak_crypto"]["sha1_signature_usage"])} instances)',
                'impact': 'SHA1 is deprecated for digital signatures due to collision vulnerabilities',
                'cwe': 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
            })
            score -= 10
            recommendations.append('Use SHA256withRSA or SHA256withECDSA for signatures')

        if crypto_analysis['weak_crypto']['ecb_mode_usage']:
            issues.append({
                'severity': 'HIGH',
                'category': 'Insecure Mode',
                'description': f'ECB cipher mode detected ({len(crypto_analysis["weak_crypto"]["ecb_mode_usage"])} instances)',
                'impact': 'ECB mode does not provide semantic security - identical plaintexts produce identical ciphertexts',
                'cwe': 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
            })
            score -= 15
            recommendations.append('Use GCM or CBC mode with proper IV - never use ECB')

        # Check for hardcoded IVs
        if crypto_analysis['crypto_parameters']['hardcoded_ivs']:
            issues.append({
                'severity': 'HIGH',
                'category': 'Static IV',
                'description': f'Hardcoded initialization vectors detected ({len(crypto_analysis["crypto_parameters"]["hardcoded_ivs"])} instances)',
                'impact': 'Static IVs break semantic security and enable pattern analysis attacks',
                'cwe': 'CWE-329: Not Using a Random IV with CBC Mode'
            })
            score -= 15
            recommendations.append('Generate random IVs using SecureRandom for each encryption operation')

        # Check for insecure Random
        if crypto_analysis['weak_crypto']['insecure_random']:
            issues.append({
                'severity': 'HIGH',
                'category': 'Weak RNG',
                'description': f'Using java.util.Random instead of SecureRandom ({len(crypto_analysis["weak_crypto"]["insecure_random"])} instances)',
                'impact': 'Random is predictable and unsuitable for cryptographic operations',
                'cwe': 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator'
            })
            score -= 10
            recommendations.append('Use SecureRandom for all cryptographic random number generation')

        # Check for proper key storage
        if crypto_analysis['crypto_libraries']['android_keystore']['used']:
            recommendations.append('✓ Good: Using Android Keystore for secure key storage')
        elif crypto_analysis['total_crypto_operations'] > 0:
            issues.append({
                'severity': 'MEDIUM',
                'category': 'Key Storage',
                'description': 'Cryptographic operations detected but no Android Keystore usage found',
                'impact': 'Keys may be stored insecurely in SharedPreferences or files',
                'cwe': 'CWE-311: Missing Encryption of Sensitive Data'
            })
            score -= 10
            recommendations.append('Use Android Keystore to securely store cryptographic keys')

        # Check crypto providers for legacy/deprecated usage
        providers = crypto_analysis.get('crypto_providers', {})

        # Warn about legacy providers
        legacy_providers_found = []
        for provider_name, provider_data in providers.items():
            if provider_data.get('used') and provider_data.get('type') == 'legacy':
                legacy_providers_found.append((provider_name, provider_data['description']))

        if legacy_providers_found:
            legacy_names = ', '.join([f"{name}" for name, desc in legacy_providers_found])
            issues.append({
                'severity': 'MEDIUM',
                'category': 'Legacy Crypto Provider',
                'description': f'Using legacy/deprecated cryptographic providers: {legacy_names}',
                'impact': 'Legacy providers may have security vulnerabilities and compatibility issues on modern Android',
                'cwe': 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
            })
            score -= 5 * len(legacy_providers_found)

            # Specific recommendations for legacy providers
            if any('spongycastle' in name for name, _ in legacy_providers_found):
                recommendations.append('Replace SpongyCastle with modern BouncyCastle')
            if any('sun_jce' in name or 'sun_security' in name for name, _ in legacy_providers_found):
                recommendations.append('Replace Sun providers with Android-compatible providers (Conscrypt, BouncyCastle)')
            if any('cryptix' in name or 'gnu_crypto' in name for name, _ in legacy_providers_found):
                recommendations.append('Replace obsolete crypto libraries with modern alternatives')

        # Positive indicators for modern providers
        if providers.get('android_keystore', {}).get('used'):
            recommendations.append('✓ Good: Using Android Keystore for hardware-backed key storage')
        if providers.get('conscrypt', {}).get('used'):
            recommendations.append('✓ Good: Using Conscrypt (Google\'s OpenSSL wrapper)')
        if providers.get('bouncycastle', {}).get('used'):
            recommendations.append('✓ Good: Using BouncyCastle crypto provider')
        if providers.get('jce', {}).get('used'):
            recommendations.append('✓ Using JCE (Java Cryptography Extension)')

        # Positive indicators (legacy check)
        if crypto_analysis['crypto_libraries']['javax_crypto']['used']:
            recommendations.append('✓ Using standard javax.crypto library')

        # Check for egregious cryptography issues and recommend WBC
        egregious_issues = []

        # Count critical crypto issues
        has_hardcoded_keys = total_keys > 0
        has_weak_encryption = len(crypto_analysis['weak_crypto'].get('des_usage', [])) > 0
        has_weak_hash = len(crypto_analysis['weak_crypto'].get('md5_usage', [])) > 0
        has_ecb_mode = len(crypto_analysis['weak_crypto'].get('ecb_mode_usage', [])) > 0
        has_static_iv = len(crypto_analysis['crypto_parameters'].get('hardcoded_ivs', [])) > 0

        if has_hardcoded_keys:
            egregious_issues.append('hardcoded keys')
        if has_weak_encryption:
            egregious_issues.append('weak encryption (DES/3DES)')
        if has_weak_hash:
            egregious_issues.append('broken hashing (MD5)')
        if has_ecb_mode:
            egregious_issues.append('insecure cipher mode (ECB)')
        if has_static_iv:
            egregious_issues.append('static initialization vectors')

        # Recommend WBC if multiple egregious issues detected
        if len(egregious_issues) >= 2 or has_hardcoded_keys:
            recommendations.append('')  # Blank line for separation
            recommendations.append('⚠️  EGREGIOUS CRYPTOGRAPHY DETECTED - Consider White-Box Cryptography (WBC) Solutions:')

            if has_hardcoded_keys:
                recommendations.append('• For hardcoded keys: WBC can hide key material in transformed cipher implementations')

            recommendations.append('• White-Box Cryptography providers for mobile:')
            recommendations.append('  - Irdeto White-Box (Commercial): Enterprise-grade WBC with key hiding and anti-tampering')
            recommendations.append('  - Arxan Application Protection (Commercial): WBC + code protection + runtime integrity')
            recommendations.append('  - Gemalto Sentinel (Commercial): WBC with licensing and DRM integration')
            recommendations.append('  - Inside Secure (Verimatrix) WBC (Commercial): Optimized for mobile performance')

            if has_weak_encryption or has_ecb_mode or has_static_iv:
                recommendations.append('• WBC protects cryptographic operations even when algorithms are exposed')
                recommendations.append('• Note: WBC is NOT a replacement for fixing broken crypto - fix weak algorithms first!')

            recommendations.append('• Combine WBC with: obfuscation, anti-debugging, integrity checks, and secure key storage')
            recommendations.append('• WBC increases reverse engineering cost but does not eliminate all crypto extraction risks')

        # Sort issues by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        issues.sort(key=lambda x: severity_order.get(x['severity'], 999))

        crypto_analysis['security_issues'] = issues
        crypto_analysis['recommendations'] = recommendations
        crypto_analysis['security_score'] = max(0, score)
        crypto_analysis['egregious_crypto_detected'] = len(egregious_issues) >= 2 or has_hardcoded_keys
        crypto_analysis['egregious_issues'] = egregious_issues

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
        resources = analysis.get('resources')  # Optional - may be None

        # Score from 0-100 based on obfuscation indicators
        # Scoring breakdown:
        # - Identifiers: 35 points
        # - Strings: 25 points
        # - Patterns: 20 points
        # - Control Flow: 10 points
        # - Resources: 10 points (if available)
        score = 0
        indicators = []

        # Identifier analysis (35 points)
        if ident['total_classes'] > 0:
            single_char_pct = ident.get('single_char_class_percentage', 0)
            meaningful_pct = ident.get('meaningful_class_percentage', 0)
            avg_length = ident.get('avg_class_length', 10)

            # High single-char percentage = likely obfuscated
            if single_char_pct > 50:
                score += 17
                indicators.append(f"Very high single-character class names ({single_char_pct:.1f}%)")
            elif single_char_pct > 30:
                score += 13
                indicators.append(f"High single-character class names ({single_char_pct:.1f}%)")
            elif single_char_pct > 10:
                score += 9
                indicators.append(f"Moderate single-character class names ({single_char_pct:.1f}%)")

            # Low meaningful percentage = likely obfuscated
            if meaningful_pct < 20:
                score += 13
                indicators.append(f"Very low meaningful class names ({meaningful_pct:.1f}%)")
            elif meaningful_pct < 40:
                score += 9
                indicators.append(f"Low meaningful class names ({meaningful_pct:.1f}%)")

            # Short average length = likely obfuscated
            if avg_length < 3:
                score += 5
                indicators.append(f"Very short average class name length ({avg_length:.1f})")
            elif avg_length < 5:
                score += 3
                indicators.append(f"Short average class name length ({avg_length:.1f})")

        # String analysis (25 points)
        if strings['total_strings'] > 0:
            encrypted_pct = strings.get('encrypted_string_percentage', 0)

            if encrypted_pct > 30:
                score += 17
                indicators.append(f"High encrypted string percentage ({encrypted_pct:.1f}%)")
            elif encrypted_pct > 10:
                score += 8
                indicators.append(f"Moderate encrypted string percentage ({encrypted_pct:.1f}%)")

            if strings.get('decryption_methods', 0) > 0:
                score += 8
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

        # Resource obfuscation (10 points) - only if resources were analyzed
        if resources:
            res_names = resources.get('resource_names', {})
            total_resources = res_names.get('total_resources', 0)

            if total_resources > 0:
                obfuscated_ratio = res_names.get('obfuscated_names', 0) / total_resources
                short_ratio = res_names.get('short_names', 0) / total_resources

                if obfuscated_ratio > 0.5:
                    score += 5
                    indicators.append(f"High resource name obfuscation ({obfuscated_ratio*100:.1f}%)")
                elif obfuscated_ratio > 0.3:
                    score += 3
                    indicators.append(f"Moderate resource name obfuscation ({obfuscated_ratio*100:.1f}%)")

                if short_ratio > 0.7:
                    score += 3
                    indicators.append(f"High short resource names ({short_ratio*100:.1f}%)")
                elif short_ratio > 0.5:
                    score += 2
                    indicators.append(f"Moderate short resource names ({short_ratio*100:.1f}%)")

            # String resource encryption
            res_strings = resources.get('string_resources', {})
            total_strings = res_strings.get('total_strings', 0)
            if total_strings > 0:
                encrypted_ratio = res_strings.get('encrypted_strings', 0) / total_strings
                if encrypted_ratio > 0.3:
                    score += 5
                    indicators.append(f"High string resource encryption ({encrypted_ratio*100:.1f}%)")
                elif encrypted_ratio > 0.1:
                    score += 3
                    indicators.append(f"Moderate string resource encryption ({encrypted_ratio*100:.1f}%)")

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

        # Validate file structure
        print("Validating file structure...")
        validation = self.validate_apk_structure(file_path)
        file_metadata['validation'] = validation

        # Display validation results
        if validation['valid']:
            print("✓ File structure is valid")
        else:
            print(f"\n⚠️  File structure issues detected:")
            for issue in validation['issues']:
                print(f"  • {issue}")
            if validation['warnings']:
                print("\n  Warnings:")
                for warning in validation['warnings']:
                    print(f"  • {warning}")
            if validation['repair_suggestions']:
                print("\n  Repair suggestions:")
                for suggestion in validation['repair_suggestions']:
                    print(f"  • {suggestion}")
            print()

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
                'control_flow': self.analyze_control_flow(sources),
                'resources': self.analyze_resources(file_path),  # Optional, returns None if androguard unavailable
                'cryptography': self.analyze_cryptography(sources)  # Crypto analysis
            }

            # Assess obfuscation likelihood
            print("\nAssessing obfuscation likelihood...")
            obfuscation_assessment = self._assess_obfuscation_likelihood(analysis)

            # Display crypto security summary
            crypto = analysis.get('cryptography', {})
            if crypto and crypto.get('total_crypto_operations', 0) > 0:
                print(f"\nCryptographic Operations Detected: {crypto['total_crypto_operations']}")
                if crypto['security_issues']:
                    print(f"⚠️  Security Issues Found: {len(crypto['security_issues'])}")
                    for issue in crypto['security_issues'][:3]:  # Show top 3
                        print(f"  • [{issue['severity']}] {issue['description']}")
                if crypto['cryptographic_keys']['total_exposed_keys'] > 0:
                    print(f"🔑 Hardcoded Keys Detected: {crypto['cryptographic_keys']['total_exposed_keys']} (CRITICAL RISK)")
                print(f"Crypto Security Score: {crypto['security_score']}/100")

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

        <div style="background-color: #e3f2fd; border-left: 4px solid #2196f3; padding: 20px; margin: 20px 0; border-radius: 4px;">
            <h3 style="color: #1565c0; margin-top: 0;">ℹ️ Understanding Obfuscation</h3>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>Obfuscation is a resilience mechanism</strong> that increases the cost and difficulty of reverse engineering.
            </p>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>What obfuscation DOES protect:</strong>
            </p>
            <ul style="color: #1565c0;">
                <li><strong>Confidentiality of Code Logic:</strong> Makes it harder to understand how your algorithms and business logic work</li>
                <li><strong>Intellectual Property:</strong> Protects proprietary algorithms and implementation details from competitors</li>
                <li><strong>Raises Reverse Engineering Cost:</strong> Forces attackers to spend more time and effort analyzing your code</li>
            </ul>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>What obfuscation does NOT provide:</strong>
            </p>
            <ul style="color: #1565c0;">
                <li><strong>NOT Anti-Tamper:</strong> Does not prevent code modification, repackaging, or injection attacks</li>
                <li><strong>NOT Integrity Checking:</strong> Does not detect if your code has been modified or tampered with</li>
                <li><strong>NOT Secret Protection:</strong> Cannot protect hardcoded API keys, passwords, or cryptographic keys (these can still be extracted)</li>
                <li><strong>NOT Runtime Protection:</strong> Does not prevent debugging, hooking, or dynamic analysis at runtime</li>
            </ul>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>For comprehensive protection, combine obfuscation with:</strong>
            </p>
            <ul style="color: #1565c0;">
                <li><strong>Integrity Protection:</strong> Code signing, certificate pinning, runtime integrity checks, anti-tamper mechanisms</li>
                <li><strong>Secret Management:</strong> Never hardcode secrets; use Android Keystore, server-side validation, secure enclaves</li>
                <li><strong>Runtime Protection:</strong> RASP, root/jailbreak detection, anti-debugging, SSL pinning</li>
            </ul>
            <p style="color: #1565c0; margin: 10px 0;">
                <em>Obfuscation is one important layer in a defense-in-depth security strategy, not a complete solution.</em>
            </p>
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

        {self._format_cryptography_html(analysis.get('cryptography', {}))}

        <h2>Identifier Analysis</h2>
        {self._format_metrics(analysis['identifiers'])}

        <h2>String Analysis</h2>
        {self._format_metrics(analysis['strings'])}

        <h2>Control Flow Complexity</h2>
        {self._format_metrics(analysis['control_flow'])}

        <h2>Package Structure</h2>
        {self._format_metrics(analysis['packages'])}

        {self._format_single_resources_html(analysis.get('resources'))}

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

        # Educational security notice
        print(f"\n{'='*60}")
        print("ℹ️  UNDERSTANDING OBFUSCATION")
        print(f"{'='*60}\n")
        print("Obfuscation is a RESILIENCE MECHANISM that increases the cost")
        print("and difficulty of reverse engineering.\n")
        print("What obfuscation DOES protect:")
        print("  ✓ Confidentiality of Code Logic: Makes algorithms & business logic harder to understand")
        print("  ✓ Intellectual Property: Protects proprietary implementation details")
        print("  ✓ Raises Reverse Engineering Cost: Forces attackers to spend more time & effort\n")
        print("What obfuscation does NOT provide:")
        print("  ✗ NOT Anti-Tamper: Does not prevent code modification or repackaging")
        print("  ✗ NOT Integrity Checking: Does not detect if code has been tampered with")
        print("  ✗ NOT Secret Protection: Cannot protect hardcoded keys/passwords (still extractable)")
        print("  ✗ NOT Runtime Protection: Does not prevent debugging or dynamic analysis\n")
        print("For comprehensive protection, combine obfuscation with:")
        print("  • Integrity: Code signing, certificate pinning, runtime integrity checks, anti-tamper")
        print("  • Secrets: Never hardcode; use Android Keystore, server-side validation")
        print("  • Runtime: RASP, root detection, anti-debugging, SSL pinning\n")
        print("Obfuscation is one important layer in defense-in-depth, not a complete solution.")

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

        # Validate file structures
        print("Validating file structures...")
        original_validation = self.validate_apk_structure(original_apk)
        obfuscated_validation = self.validate_apk_structure(obfuscated_apk)

        original_metadata['validation'] = original_validation
        obfuscated_metadata['validation'] = obfuscated_validation

        # Display validation results
        print("Original file:")
        if original_validation['valid']:
            print("  ✓ File structure is valid")
        else:
            print(f"  ⚠️  File structure issues detected:")
            for issue in original_validation['issues']:
                print(f"    • {issue}")

        print("Obfuscated file:")
        if obfuscated_validation['valid']:
            print("  ✓ File structure is valid")
        else:
            print(f"  ⚠️  File structure issues detected:")
            for issue in obfuscated_validation['issues']:
                print(f"    • {issue}")
            if obfuscated_validation['repair_suggestions']:
                print("\n  Repair suggestions:")
                for suggestion in obfuscated_validation['repair_suggestions']:
                    print(f"    • {suggestion}")
        print()

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
                'control_flow': self.analyze_control_flow(original_sources),
                'resources': self.analyze_resources(original_apk),  # Optional
                'cryptography': self.analyze_cryptography(original_sources)  # Crypto analysis
            }

            print("Analyzing obfuscated file...")
            obfuscated_analysis = {
                'identifiers': self.analyze_identifiers(obfuscated_sources),
                'packages': self.analyze_package_structure(obfuscated_sources),
                'patterns': self.detect_obfuscation_patterns(obfuscated_sources),
                'strings': self.analyze_strings(obfuscated_sources),
                'control_flow': self.analyze_control_flow(obfuscated_sources),
                'resources': self.analyze_resources(obfuscated_apk),  # Optional
                'cryptography': self.analyze_cryptography(obfuscated_sources)  # Crypto analysis
            }

            # Display crypto security comparison
            orig_crypto = original_analysis.get('cryptography', {})
            obf_crypto = obfuscated_analysis.get('cryptography', {})
            if orig_crypto.get('total_crypto_operations', 0) > 0 or obf_crypto.get('total_crypto_operations', 0) > 0:
                print("\n" + "="*60)
                print("Cryptographic Security Analysis")
                print("="*60)
                print(f"Original - Crypto Ops: {orig_crypto.get('total_crypto_operations', 0)}, "
                      f"Security Score: {orig_crypto.get('security_score', 'N/A')}/100")
                print(f"Obfuscated - Crypto Ops: {obf_crypto.get('total_crypto_operations', 0)}, "
                      f"Security Score: {obf_crypto.get('security_score', 'N/A')}/100")

                orig_keys = orig_crypto.get('cryptographic_keys', {}).get('total_exposed_keys', 0)
                obf_keys = obf_crypto.get('cryptographic_keys', {}).get('total_exposed_keys', 0)
                if orig_keys > 0 or obf_keys > 0:
                    print(f"\n🔑 Hardcoded Keys - Original: {orig_keys}, Obfuscated: {obf_keys}")
                    if obf_keys >= orig_keys and obf_keys > 0:
                        print("⚠️  WARNING: Obfuscation did NOT hide hardcoded keys!")

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

        # Scoring breakdown for comparison:
        # - Identifiers: 35 points
        # - Strings: 25 points
        # - Control Flow: 20 points
        # - Packages: 10 points
        # - Resources: 10 points (if available)

        # Identifier obfuscation (35 points)
        orig_ident = original['identifiers']
        obf_ident = obfuscated['identifiers']

        if orig_ident['total_classes'] > 0 and obf_ident['total_classes'] > 0:
            # Single char increase
            single_char_increase = (
                obf_ident.get('single_char_class_percentage', 0) -
                orig_ident.get('single_char_class_percentage', 0)
            )
            score += min(single_char_increase * 0.5, 13)

            # Meaningful name decrease
            meaningful_decrease = (
                orig_ident.get('meaningful_class_percentage', 0) -
                obf_ident.get('meaningful_class_percentage', 0)
            )
            score += min(meaningful_decrease * 0.3, 13)

            # Average length decrease
            length_decrease = (
                orig_ident.get('avg_class_length', 10) -
                obf_ident.get('avg_class_length', 10)
            )
            if length_decrease > 0:
                score += min(length_decrease * 2, 9)

        comparison['changes']['identifier_score'] = score

        # String obfuscation (25 points)
        orig_str = original['strings']
        obf_str = obfuscated['strings']

        string_score = 0
        if orig_str['total_strings'] > 0 and obf_str['total_strings'] > 0:
            encrypted_increase = (
                obf_str.get('encrypted_string_percentage', 0) -
                orig_str.get('encrypted_string_percentage', 0)
            )
            string_score += min(encrypted_increase * 0.5, 17)

            if obf_str.get('decryption_methods', 0) > 0:
                string_score += 8

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

        # Resource obfuscation (10 points) - only if both have resource analysis
        orig_res = original.get('resources')
        obf_res = obfuscated.get('resources')

        res_score = 0
        if orig_res and obf_res:
            orig_res_names = orig_res.get('resource_names', {})
            obf_res_names = obf_res.get('resource_names', {})

            orig_total = orig_res_names.get('total_resources', 0)
            obf_total = obf_res_names.get('total_resources', 0)

            if orig_total > 0 and obf_total > 0:
                # Resource name obfuscation increase
                orig_obf_ratio = orig_res_names.get('obfuscated_names', 0) / orig_total
                obf_obf_ratio = obf_res_names.get('obfuscated_names', 0) / obf_total
                obf_increase = (obf_obf_ratio - orig_obf_ratio) * 100

                if obf_increase > 0:
                    res_score += min(obf_increase * 0.1, 5)

                # Short name ratio increase
                orig_short_ratio = orig_res_names.get('short_names', 0) / orig_total
                obf_short_ratio = obf_res_names.get('short_names', 0) / obf_total
                short_increase = (obf_short_ratio - orig_short_ratio) * 100

                if short_increase > 0:
                    res_score += min(short_increase * 0.05, 3)

            # String resource encryption
            orig_res_str = orig_res.get('string_resources', {})
            obf_res_str = obf_res.get('string_resources', {})

            orig_str_total = orig_res_str.get('total_strings', 0)
            obf_str_total = obf_res_str.get('total_strings', 0)

            if orig_str_total > 0 and obf_str_total > 0:
                orig_enc_ratio = orig_res_str.get('encrypted_strings', 0) / orig_str_total
                obf_enc_ratio = obf_res_str.get('encrypted_strings', 0) / obf_str_total
                enc_increase = (obf_enc_ratio - orig_enc_ratio) * 100

                if enc_increase > 0:
                    res_score += min(enc_increase * 0.1, 2)

        score += res_score
        comparison['changes']['resource_score'] = res_score

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

        <div style="background-color: #e3f2fd; border-left: 4px solid #2196f3; padding: 20px; margin: 20px 0; border-radius: 4px;">
            <h3 style="color: #1565c0; margin-top: 0;">ℹ️ Understanding Obfuscation</h3>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>Obfuscation is a resilience mechanism</strong> that increases the cost and difficulty of reverse engineering.
            </p>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>What obfuscation DOES protect:</strong>
            </p>
            <ul style="color: #1565c0;">
                <li><strong>Confidentiality of Code Logic:</strong> Makes it harder to understand how your algorithms and business logic work</li>
                <li><strong>Intellectual Property:</strong> Protects proprietary algorithms and implementation details from competitors</li>
                <li><strong>Raises Reverse Engineering Cost:</strong> Forces attackers to spend more time and effort analyzing your code</li>
            </ul>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>What obfuscation does NOT provide:</strong>
            </p>
            <ul style="color: #1565c0;">
                <li><strong>NOT Anti-Tamper:</strong> Does not prevent code modification, repackaging, or injection attacks</li>
                <li><strong>NOT Integrity Checking:</strong> Does not detect if your code has been modified or tampered with</li>
                <li><strong>NOT Secret Protection:</strong> Cannot protect hardcoded API keys, passwords, or cryptographic keys (these can still be extracted)</li>
                <li><strong>NOT Runtime Protection:</strong> Does not prevent debugging, hooking, or dynamic analysis at runtime</li>
            </ul>
            <p style="color: #1565c0; margin: 10px 0;">
                <strong>For comprehensive protection, combine obfuscation with:</strong>
            </p>
            <ul style="color: #1565c0;">
                <li><strong>Integrity Protection:</strong> Code signing, certificate pinning, runtime integrity checks, anti-tamper mechanisms</li>
                <li><strong>Secret Management:</strong> Never hardcode secrets; use Android Keystore, server-side validation, secure enclaves</li>
                <li><strong>Runtime Protection:</strong> RASP, root/jailbreak detection, anti-debugging, SSL pinning</li>
            </ul>
            <p style="color: #1565c0; margin: 10px 0;">
                <em>Obfuscation is one important layer in a defense-in-depth security strategy, not a complete solution.</em>
            </p>
        </div>

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

        {self._format_resources_html(comparison['original'].get('resources'), comparison['obfuscated'].get('resources'))}

        <h2>🔐 Cryptographic Security Comparison</h2>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
            <div>
                <h3>Original APK</h3>
                {self._format_cryptography_html(comparison['original'].get('cryptography', {}))}
            </div>
            <div>
                <h3>Obfuscated APK</h3>
                {self._format_cryptography_html(comparison['obfuscated'].get('cryptography', {}))}
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

        # Validation results
        validation = metadata.get('validation', {})
        if validation:
            html += '<h3 style="color: #34495e; margin-top: 20px;">🔍 File Structure Validation</h3>'

            if validation.get('valid'):
                html += '<div style="background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; padding: 15px; margin: 10px 0;">'
                html += '<div style="color: #155724; font-weight: bold;">✓ File structure is valid</div>'
                html += '</div>'
            else:
                # Issues section
                issues = validation.get('issues', [])
                if issues:
                    html += '<div style="background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; padding: 15px; margin: 10px 0;">'
                    html += '<div style="color: #721c24; font-weight: bold; margin-bottom: 10px;">⚠️ File Structure Issues Detected</div>'
                    html += '<ul style="color: #721c24; margin: 10px 0; padding-left: 20px;">'
                    for issue in issues:
                        html += f'<li style="margin: 5px 0;">{issue}</li>'
                    html += '</ul>'
                    html += '</div>'

                # Warnings section
                warnings = validation.get('warnings', [])
                if warnings:
                    html += '<div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 15px; margin: 10px 0;">'
                    html += '<div style="color: #856404; font-weight: bold; margin-bottom: 10px;">⚠ Warnings</div>'
                    html += '<ul style="color: #856404; margin: 10px 0; padding-left: 20px;">'
                    for warning in warnings:
                        html += f'<li style="margin: 5px 0;">{warning}</li>'
                    html += '</ul>'
                    html += '</div>'

                # Repair suggestions section
                repair_suggestions = validation.get('repair_suggestions', [])
                if repair_suggestions:
                    html += '<div style="background: #e7f3ff; border: 1px solid #2196f3; border-radius: 4px; padding: 15px; margin: 10px 0;">'
                    html += '<div style="color: #0d47a1; font-weight: bold; margin-bottom: 10px;">🔧 Repair Suggestions</div>'
                    html += '<ul style="color: #0d47a1; margin: 10px 0; padding-left: 20px;">'
                    for suggestion in repair_suggestions:
                        html += f'<li style="margin: 5px 0;"><code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 13px;">{suggestion}</code></li>'
                    html += '</ul>'
                    html += '</div>'

            # Show checks performed
            checks = validation.get('checks_performed', {})
            if checks:
                html += '<div style="margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 4px; font-size: 13px;">'
                html += '<strong>Validation Checks Performed:</strong> '
                performed_checks = [name.replace('_', ' ').title() for name, done in checks.items() if done]
                html += ', '.join(performed_checks) if performed_checks else 'None'
                html += '</div>'

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

    def _format_cryptography_html(self, crypto):
        """
        Format cryptographic analysis for HTML report

        Args:
            crypto: Cryptography analysis dictionary

        Returns:
            HTML string with formatted crypto section
        """
        if not crypto or crypto.get('total_crypto_operations', 0) == 0:
            return '''
        <h2>🔐 Cryptographic Analysis</h2>
        <div style="background-color: #e8f5e9; padding: 20px; border-radius: 8px; border-left: 4px solid #4caf50;">
            <p><strong>✓ No cryptographic operations detected</strong></p>
            <p>This file does not appear to contain cryptographic code.</p>
        </div>
'''

        html = '<h2>🔐 Cryptographic Security Analysis</h2>'

        # Security Score Box
        score = crypto.get('security_score', 0)
        score_color = '#4caf50' if score >= 80 else '#ff9800' if score >= 50 else '#f44336'
        score_status = 'GOOD' if score >= 80 else 'FAIR' if score >= 50 else 'POOR'

        html += f'''
        <div style="background: {score_color}; color: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin: 0; color: white;">Crypto Security Score: {score}/100 ({score_status})</h3>
            <p style="margin: 5px 0 0 0; color: white;">Total Cryptographic Operations: {crypto.get('total_crypto_operations', 0)}</p>
        </div>
'''

        # Security Issues (CRITICAL)
        issues = crypto.get('security_issues', [])
        if issues:
            html += '<div style="background: #ffebee; padding: 20px; border-radius: 8px; border-left: 4px solid #f44336; margin: 20px 0;">'
            html += f'<h3 style="color: #c62828; margin-top: 0;">⚠️ Security Issues Found ({len(issues)})</h3>'

            for issue in issues:
                severity_color = '#d32f2f' if issue['severity'] == 'CRITICAL' else '#f57c00' if issue['severity'] == 'HIGH' else '#fbc02d'
                html += f'''
                <div style="background: white; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 3px solid {severity_color};">
                    <div style="font-weight: bold; color: {severity_color};">[{issue['severity']}] {issue['category']}</div>
                    <div style="margin: 5px 0;"><strong>Issue:</strong> {issue['description']}</div>
                    <div style="margin: 5px 0;"><strong>Impact:</strong> {issue['impact']}</div>
                    <div style="margin: 5px 0; color: #666; font-size: 12px;"><strong>CWE:</strong> {issue.get('cwe', 'N/A')}</div>
                </div>
'''
            html += '</div>'

        # Hardcoded Keys (CRITICAL SECTION)
        keys = crypto.get('cryptographic_keys', {})
        total_keys = keys.get('total_exposed_keys', 0)
        if total_keys > 0:
            html += '<div style="background: #ffebee; padding: 20px; border-radius: 8px; border-left: 4px solid #d32f2f; margin: 20px 0;">'
            html += f'<h3 style="color: #c62828; margin-top: 0;">🔑 HARDCODED CRYPTOGRAPHIC KEYS ({total_keys} found)</h3>'
            html += '<p style="color: #d32f2f; font-weight: bold;">CRITICAL SECURITY RISK: Cryptographic keys found in source code!</p>'

            # Hardcoded SecretKeySpec
            if keys.get('hardcoded_keys'):
                html += '<h4 style="color: #c62828;">SecretKeySpec with Hardcoded Keys:</h4><ul>'
                for key in keys['hardcoded_keys'][:5]:
                    html += f'<li><strong>File:</strong> {key["file"]}<br><code style="background: #f5f5f5; padding: 5px; display: block; margin: 5px 0; overflow-x: auto;">{key["context"][:200]}</code></li>'
                if len(keys['hardcoded_keys']) > 5:
                    html += f'<li><em>... and {len(keys["hardcoded_keys"]) - 5} more</em></li>'
                html += '</ul>'

            # PEM Keys
            if keys.get('pem_keys'):
                html += '<h4 style="color: #c62828;">PEM-Formatted Keys:</h4><ul>'
                for key in keys['pem_keys'][:5]:
                    html += f'<li><strong>File:</strong> {key["file"]}<br><strong>Type:</strong> {key["type"]}<br><code style="background: #f5f5f5; padding: 5px; display: block; margin: 5px 0;">{key["key_preview"]}</code></li>'
                if len(keys['pem_keys']) > 5:
                    html += f'<li><em>... and {len(keys["pem_keys"]) - 5} more</em></li>'
                html += '</ul>'

            # Base64 Keys
            if keys.get('base64_keys'):
                html += '<h4 style="color: #f57c00;">Potential Base64-Encoded Keys:</h4><ul>'
                for key in keys['base64_keys'][:5]:
                    html += f'<li><strong>File:</strong> {key["file"]}<br><strong>Possible Key Size:</strong> {key["possible_key_size"]} bits<br><code style="background: #f5f5f5; padding: 5px;">{key["base64_string"]}</code></li>'
                if len(keys['base64_keys']) > 5:
                    html += f'<li><em>... and {len(keys["base64_keys"]) - 5} more</em></li>'
                html += '</ul>'

            # Hex Keys
            if keys.get('hex_keys'):
                html += '<h4 style="color: #f57c00;">Potential Hex-Encoded Keys:</h4><ul>'
                for key in keys['hex_keys'][:5]:
                    html += f'<li><strong>File:</strong> {key["file"]}<br><strong>Possible Key Size:</strong> {key["possible_key_size"]} bits<br><code style="background: #f5f5f5; padding: 5px;">{key["hex_string"]}</code></li>'
                if len(keys['hex_keys']) > 5:
                    html += f'<li><em>... and {len(keys["hex_keys"]) - 5} more</em></li>'
                html += '</ul>'

            html += '</div>'

        # Weak Cryptography
        weak = crypto.get('weak_crypto', {})
        has_weak = any([weak.get('md5_usage'), weak.get('des_usage'), weak.get('ecb_mode_usage'),
                       weak.get('sha1_signature_usage'), weak.get('insecure_random')])

        if has_weak:
            html += '<div style="background: #fff3e0; padding: 20px; border-radius: 8px; border-left: 4px solid #f57c00; margin: 20px 0;">'
            html += '<h3 style="color: #e65100; margin-top: 0;">⚠️ Weak/Insecure Cryptography Detected</h3>'

            if weak.get('md5_usage'):
                html += f'<div style="margin: 10px 0;"><strong style="color: #d32f2f;">MD5 Usage ({len(weak["md5_usage"])} instances):</strong> MD5 is cryptographically broken<ul>'
                for item in weak['md5_usage'][:3]:
                    html += f'<li>File: {item["file"]}</li>'
                html += '</ul></div>'

            if weak.get('des_usage'):
                html += f'<div style="margin: 10px 0;"><strong style="color: #d32f2f;">DES/3DES Usage ({len(weak["des_usage"])} instances):</strong> Vulnerable to brute force<ul>'
                for item in weak['des_usage'][:3]:
                    html += f'<li>File: {item["file"]}</li>'
                html += '</ul></div>'

            if weak.get('ecb_mode_usage'):
                html += f'<div style="margin: 10px 0;"><strong style="color: #f57c00;">ECB Mode ({len(weak["ecb_mode_usage"])} instances):</strong> Insecure cipher mode<ul>'
                for item in weak['ecb_mode_usage'][:3]:
                    html += f'<li>File: {item["file"]}</li>'
                html += '</ul></div>'

            if weak.get('sha1_signature_usage'):
                html += f'<div style="margin: 10px 0;"><strong style="color: #f57c00;">SHA1 Signatures ({len(weak["sha1_signature_usage"])} instances):</strong> Deprecated for signatures<ul>'
                for item in weak['sha1_signature_usage'][:3]:
                    html += f'<li>File: {item["file"]}</li>'
                html += '</ul></div>'

            if weak.get('insecure_random'):
                html += f'<div style="margin: 10px 0;"><strong style="color: #f57c00;">Insecure Random ({len(weak["insecure_random"])} instances):</strong> Using Random instead of SecureRandom<ul>'
                for item in weak['insecure_random'][:3]:
                    html += f'<li>File: {item["file"]}</li>'
                html += '</ul></div>'

            html += '</div>'

        # Crypto Operations Summary
        ops = crypto.get('crypto_operations', {})
        if crypto.get('total_crypto_operations', 0) > 0:
            html += '<div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;">'
            html += '<h3 style="color: #1565c0; margin-top: 0;">Cryptographic Operations Found</h3>'

            if ops.get('cipher_instances'):
                html += f'<div style="margin: 10px 0;"><strong>Cipher Instances ({len(ops["cipher_instances"])}):</strong><ul>'
                for op in ops['cipher_instances'][:5]:
                    html += f'<li><strong>Algorithm:</strong> {op["algorithm"]} | <strong>File:</strong> {op["file"]}</li>'
                html += '</ul></div>'

            if ops.get('key_generators'):
                html += f'<div style="margin: 10px 0;"><strong>Key Generators ({len(ops["key_generators"])}):</strong><ul>'
                for op in ops['key_generators'][:5]:
                    html += f'<li><strong>Algorithm:</strong> {op["algorithm"]} | <strong>File:</strong> {op["file"]}</li>'
                html += '</ul></div>'

            if ops.get('message_digests'):
                html += f'<div style="margin: 10px 0;"><strong>Message Digests ({len(ops["message_digests"])}):</strong><ul>'
                for op in ops['message_digests'][:5]:
                    html += f'<li><strong>Algorithm:</strong> {op["algorithm"]} | <strong>File:</strong> {op["file"]}</li>'
                html += '</ul></div>'

            html += '</div>'

        # Crypto Providers Used (comprehensive breakdown)
        providers = crypto.get('crypto_providers', {})
        modern_providers = [(name, data) for name, data in providers.items() if data.get('used') and data.get('type') == 'modern']
        standard_providers = [(name, data) for name, data in providers.items() if data.get('used') and data.get('type') == 'standard']
        legacy_providers = [(name, data) for name, data in providers.items() if data.get('used') and data.get('type') == 'legacy']

        if modern_providers or standard_providers or legacy_providers:
            html += '<div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">'
            html += '<h3 style="margin-top: 0;">🔧 Cryptographic Providers Detected</h3>'

            # Modern providers (good)
            if modern_providers:
                html += '<div style="margin: 15px 0;">'
                html += '<h4 style="color: #2e7d32;">✓ Modern Providers (Recommended)</h4>'
                html += '<ul>'
                for name, data in modern_providers:
                    html += f'<li><strong>{data["description"]}</strong><br>'
                    html += f'<span style="color: #666; font-size: 13px;">Used in {data["count"]} classes</span></li>'
                html += '</ul>'
                html += '</div>'

            # Standard providers (neutral)
            if standard_providers:
                html += '<div style="margin: 15px 0;">'
                html += '<h4 style="color: #1976d2;">Standard Java Crypto APIs</h4>'
                html += '<ul>'
                for name, data in standard_providers:
                    html += f'<li><strong>{data["description"]}</strong><br>'
                    html += f'<span style="color: #666; font-size: 13px;">Used in {data["count"]} classes</span></li>'
                html += '</ul>'
                html += '</div>'

            # Legacy providers (warning)
            if legacy_providers:
                html += '<div style="margin: 15px 0; background: #fff3e0; padding: 15px; border-radius: 4px; border-left: 3px solid #f57c00;">'
                html += '<h4 style="color: #e65100; margin-top: 0;">⚠️ Legacy/Deprecated Providers</h4>'
                html += '<ul style="color: #e65100;">'
                for name, data in legacy_providers:
                    html += f'<li><strong>{data["description"]}</strong><br>'
                    html += f'<span style="color: #666; font-size: 13px;">Used in {data["count"]} classes - Consider migrating to modern alternatives</span></li>'
                html += '</ul>'
                html += '</div>'

            html += '</div>'

        # Crypto Libraries Used (legacy display for backward compatibility)
        libs = crypto.get('crypto_libraries', {})
        libs_used = [name for name, data in libs.items() if data.get('used')]
        if libs_used and not (modern_providers or standard_providers or legacy_providers):
            # Only show if providers section wasn't shown
            html += '<div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">'
            html += '<h3 style="margin-top: 0;">Cryptographic Libraries Detected</h3><ul>'
            for lib_name in libs_used:
                lib_data = libs[lib_name]
                html += f'<li><strong>{lib_name}:</strong> {lib_data["count"]} classes</li>'
            html += '</ul></div>'

        # White-Box Cryptography Recommendation (Special Section if egregious issues)
        if crypto.get('egregious_crypto_detected'):
            egregious_issues = crypto.get('egregious_issues', [])
            issues_list = ', '.join(egregious_issues)

            html += '<div style="background: #fff3e0; padding: 25px; border-radius: 8px; border-left: 6px solid #ff6f00; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.15);">'
            html += '<h3 style="color: #e65100; margin-top: 0;">⚠️ EGREGIOUS CRYPTOGRAPHY DETECTED</h3>'
            html += f'<p style="color: #e65100; font-weight: bold;">Critical Issues Found: {issues_list}</p>'

            html += '<div style="background: white; padding: 20px; border-radius: 6px; margin: 15px 0;">'
            html += '<h4 style="color: #d84315; margin-top: 0;">🔐 Consider White-Box Cryptography (WBC) Solutions</h4>'

            html += '<p style="margin: 10px 0;">White-Box Cryptography can provide additional protection when standard crypto has severe weaknesses:</p>'

            html += '<table style="width: 100%; border-collapse: collapse; margin: 15px 0;">'
            html += '<tr style="background: #f5f5f5;"><th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Provider</th><th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Features</th></tr>'

            html += '<tr><td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Irdeto White-Box</strong><br><span style="color: #666; font-size: 12px;">Commercial</span></td>'
            html += '<td style="padding: 10px; border-bottom: 1px solid #eee;">Enterprise-grade WBC with key hiding, anti-tampering, and DRM support</td></tr>'

            html += '<tr><td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Arxan Application Protection</strong><br><span style="color: #666; font-size: 12px;">Commercial</span></td>'
            html += '<td style="padding: 10px; border-bottom: 1px solid #eee;">WBC + code protection + runtime integrity + anti-debugging</td></tr>'

            html += '<tr><td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Gemalto Sentinel (Thales)</strong><br><span style="color: #666; font-size: 12px;">Commercial</span></td>'
            html += '<td style="padding: 10px; border-bottom: 1px solid #eee;">WBC with software licensing, DRM integration, and cloud key management</td></tr>'

            html += '<tr><td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Inside Secure (Verimatrix)</strong><br><span style="color: #666; font-size: 12px;">Commercial</span></td>'
            html += '<td style="padding: 10px; border-bottom: 1px solid #eee;">Mobile-optimized WBC with low performance overhead</td></tr>'

            html += '</table>'

            html += '<div style="background: #ffebee; padding: 15px; border-radius: 4px; margin: 15px 0; border-left: 3px solid #d32f2f;">'
            html += '<h5 style="margin-top: 0; color: #c62828;">⚠️ Important WBC Limitations</h5>'
            html += '<ul style="margin: 10px 0; color: #c62828;">'
            html += '<li><strong>WBC is NOT a replacement for fixing broken crypto</strong> - Fix weak algorithms (MD5, DES) first!</li>'
            html += '<li>WBC increases reverse engineering cost but does not eliminate extraction risks</li>'
            html += '<li>Performance impact: WBC can be 10-100x slower than standard crypto</li>'
            html += '<li>WBC works best for protecting small, critical crypto operations (not bulk encryption)</li>'
            html += '</ul>'
            html += '</div>'

            html += '<div style="background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 15px 0;">'
            html += '<h5 style="margin-top: 0; color: #1565c0;">✓ Best Practices with WBC</h5>'
            html += '<ul style="margin: 10px 0; color: #1565c0;">'
            html += '<li>Combine WBC with obfuscation, anti-debugging, and runtime integrity checks</li>'
            html += '<li>Use WBC for authentication tokens, license verification, and session keys</li>'
            html += '<li>Store WBC implementations in native code (C/C++) for added protection</li>'
            html += '<li>Implement key diversification - different keys per device/user</li>'
            html += '<li>Use Android Keystore for additional hardware-backed key protection</li>'
            html += '</ul>'
            html += '</div>'

            html += '</div></div>'

        # Recommendations
        recommendations = crypto.get('recommendations', [])
        if recommendations:
            html += '<div style="background: #e8f5e9; padding: 20px; border-radius: 8px; border-left: 4px solid #4caf50; margin: 20px 0;">'
            html += '<h3 style="color: #2e7d32; margin-top: 0;">📋 Recommendations</h3><ul>'
            for rec in recommendations:
                # Skip WBC recommendations in main list if already shown in special section
                if crypto.get('egregious_crypto_detected') and ('WBC' in rec or 'White-Box' in rec or 'Irdeto' in rec or 'Arxan' in rec):
                    continue
                if rec.startswith('✓'):
                    html += f'<li style="color: #2e7d32;">{rec}</li>'
                elif rec.strip() == '':
                    continue  # Skip blank lines
                else:
                    html += f'<li>{rec}</li>'
            html += '</ul></div>'

        return html

    def _format_single_resources_html(self, resources):
        """
        Format resource analysis for single file HTML report

        Args:
            resources: Resource analysis dictionary or None

        Returns:
            HTML string with formatted resource section
        """
        if not resources:
            return '''
        <h2>Resource Analysis</h2>
        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
            <p><strong>ℹ️ Resource analysis not available</strong></p>
            <p>Install androguard to enable resource obfuscation analysis:</p>
            <pre style="background: #f8f9fa; padding: 10px; border-radius: 3px;">pip install androguard</pre>
        </div>
'''

        res_names = resources.get('resource_names', {})
        res_strings = resources.get('string_resources', {})
        res_types = resources.get('resource_types', {})
        indicators = resources.get('obfuscation_indicators', {})

        total_resources = res_names.get('total_resources', 0)

        html = '<h2>Resource Analysis</h2>'
        html += '<div style="background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin: 10px 0;">'

        # Resource names summary
        html += '<h3>Resource Names</h3>'
        html += f'<div class="metric"><strong>Total Resources:</strong> {total_resources}</div>'
        html += f'<div class="metric"><strong>Obfuscated Names:</strong> {res_names.get("obfuscated_names", 0)} ({(res_names.get("obfuscated_names", 0)/max(total_resources,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Short Names (≤2 chars):</strong> {res_names.get("short_names", 0)} ({(res_names.get("short_names", 0)/max(total_resources,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Meaningful Names:</strong> {res_names.get("meaningful_names", 0)} ({(res_names.get("meaningful_names", 0)/max(total_resources,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Average Name Length:</strong> {res_names.get("avg_name_length", 0):.2f}</div>'

        # String resources
        total_strings = res_strings.get('total_strings', 0)
        if total_strings > 0:
            html += '<h3>String Resources</h3>'
            html += f'<div class="metric"><strong>Total String Resources:</strong> {total_strings}</div>'
            html += f'<div class="metric"><strong>Encrypted Strings:</strong> {res_strings.get("encrypted_strings", 0)} ({(res_strings.get("encrypted_strings", 0)/max(total_strings,1)*100):.1f}%)</div>'
            html += f'<div class="metric"><strong>Base64 Encoded:</strong> {res_strings.get("base64_strings", 0)}</div>'
            html += f'<div class="metric"><strong>Average Entropy:</strong> {res_strings.get("avg_string_entropy", 0):.2f}</div>'

        # Resource types breakdown
        if res_types:
            html += '<h3>Resource Types</h3>'
            html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">'
            for res_type, count in sorted(res_types.items(), key=lambda x: x[1], reverse=True)[:10]:
                html += f'<div class="metric"><strong>{res_type}:</strong> {count}</div>'
            html += '</div>'

        # Obfuscation indicators
        if any(indicators.values()):
            html += '<h3>Obfuscation Indicators</h3>'
            if indicators.get('high_obfuscated_ratio'):
                html += '<div style="color: #4caf50;">✓ High resource name obfuscation detected</div>'
            if indicators.get('short_name_dominance'):
                html += '<div style="color: #4caf50;">✓ Short resource names dominant</div>'
            if indicators.get('sequential_naming'):
                html += '<div style="color: #4caf50;">✓ Sequential naming pattern detected</div>'
            if indicators.get('encrypted_string_ratio'):
                html += '<div style="color: #4caf50;">✓ High string resource encryption</div>'

        html += '</div>'
        return html

    def _format_resources_html(self, orig_resources, obf_resources):
        """
        Format resource analysis comparison for HTML report

        Args:
            orig_resources: Original resource analysis dictionary or None
            obf_resources: Obfuscated resource analysis dictionary or None

        Returns:
            HTML string with formatted resource comparison section
        """
        if not orig_resources or not obf_resources:
            if not orig_resources and not obf_resources:
                return '''
        <h2>Resource Analysis</h2>
        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
            <p><strong>ℹ️ Resource analysis not available</strong></p>
            <p>Install androguard to enable resource obfuscation analysis:</p>
            <pre style="background: #f8f9fa; padding: 10px; border-radius: 3px;">pip install androguard</pre>
        </div>
'''
            else:
                return ''  # Skip if only one has resources

        html = '<h2>Resource Obfuscation</h2>'
        html += '<div class="comparison">'

        # Original
        html += '<div class="comparison-item">'
        html += '<h3>Original APK</h3>'
        orig_names = orig_resources.get('resource_names', {})
        orig_strings = orig_resources.get('string_resources', {})
        orig_total = orig_names.get('total_resources', 0)

        html += f'<div class="metric"><strong>Total Resources:</strong> {orig_total}</div>'
        html += f'<div class="metric"><strong>Obfuscated Names:</strong> {orig_names.get("obfuscated_names", 0)} ({(orig_names.get("obfuscated_names", 0)/max(orig_total,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Short Names:</strong> {orig_names.get("short_names", 0)} ({(orig_names.get("short_names", 0)/max(orig_total,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Avg Name Length:</strong> {orig_names.get("avg_name_length", 0):.2f}</div>'

        orig_str_total = orig_strings.get('total_strings', 0)
        if orig_str_total > 0:
            html += f'<div class="metric"><strong>String Resources:</strong> {orig_str_total}</div>'
            html += f'<div class="metric"><strong>Encrypted Strings:</strong> {orig_strings.get("encrypted_strings", 0)} ({(orig_strings.get("encrypted_strings", 0)/max(orig_str_total,1)*100):.1f}%)</div>'

        html += '</div>'

        # Obfuscated
        html += '<div class="comparison-item">'
        html += '<h3>Obfuscated APK</h3>'
        obf_names = obf_resources.get('resource_names', {})
        obf_strings = obf_resources.get('string_resources', {})
        obf_total = obf_names.get('total_resources', 0)

        html += f'<div class="metric"><strong>Total Resources:</strong> {obf_total}</div>'
        html += f'<div class="metric"><strong>Obfuscated Names:</strong> {obf_names.get("obfuscated_names", 0)} ({(obf_names.get("obfuscated_names", 0)/max(obf_total,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Short Names:</strong> {obf_names.get("short_names", 0)} ({(obf_names.get("short_names", 0)/max(obf_total,1)*100):.1f}%)</div>'
        html += f'<div class="metric"><strong>Avg Name Length:</strong> {obf_names.get("avg_name_length", 0):.2f}</div>'

        obf_str_total = obf_strings.get('total_strings', 0)
        if obf_str_total > 0:
            html += f'<div class="metric"><strong>String Resources:</strong> {obf_str_total}</div>'
            html += f'<div class="metric"><strong>Encrypted Strings:</strong> {obf_strings.get("encrypted_strings", 0)} ({(obf_strings.get("encrypted_strings", 0)/max(obf_str_total,1)*100):.1f}%)</div>'

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

        # Educational security notice
        print(f"\n{'='*60}")
        print("ℹ️  UNDERSTANDING OBFUSCATION")
        print(f"{'='*60}\n")
        print("Obfuscation is a RESILIENCE MECHANISM that increases the cost")
        print("and difficulty of reverse engineering.\n")
        print("What obfuscation DOES protect:")
        print("  ✓ Confidentiality of Code Logic: Makes algorithms & business logic harder to understand")
        print("  ✓ Intellectual Property: Protects proprietary implementation details")
        print("  ✓ Raises Reverse Engineering Cost: Forces attackers to spend more time & effort\n")
        print("What obfuscation does NOT provide:")
        print("  ✗ NOT Anti-Tamper: Does not prevent code modification or repackaging")
        print("  ✗ NOT Integrity Checking: Does not detect if code has been tampered with")
        print("  ✗ NOT Secret Protection: Cannot protect hardcoded keys/passwords (still extractable)")
        print("  ✗ NOT Runtime Protection: Does not prevent debugging or dynamic analysis\n")
        print("For comprehensive protection, combine obfuscation with:")
        print("  • Integrity: Code signing, certificate pinning, runtime integrity checks, anti-tamper")
        print("  • Secrets: Never hardcode; use Android Keystore, server-side validation")
        print("  • Runtime: RASP, root detection, anti-debugging, SSL pinning\n")
        print("Obfuscation is one important layer in defense-in-depth, not a complete solution.")

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

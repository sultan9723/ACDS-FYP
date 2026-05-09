"""
PE Header Binary Detection Service
===================================
Layer 2: Static PE header feature extraction and ransomware classification.

Extracts PE header features from Windows executables and uses Gradient Boosting
model to detect ransomware binaries (ransomware-only filtered, no generic malware).

Version: 1.0.0
"""

# Suppress sklearn version warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

import os
import json
import joblib
import logging
import struct
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class PEHeaderExtractor:
    """Extract PE header features from Windows executables."""
    
    # PE feature indices corresponding to model training
    PE_FEATURES_COUNT = 25
    
    @staticmethod
    def extract_features(binary_path: str) -> Optional[List[float]]:
        """
        Extract PE header features from a binary file.
        
        Returns a list of 25 features matching the model's training features.
        Returns None if extraction fails.
        """
        try:
            # Try to use pefile library if available
            try:
                import pefile
                return PEHeaderExtractor._extract_with_pefile(binary_path)
            except ImportError:
                logger.warning("pefile not installed, using fallback extraction")
                return PEHeaderExtractor._extract_fallback_features(binary_path)
        except Exception as e:
            logger.error(f"Error extracting PE features: {e}")
            return None
    
    @staticmethod
    def _extract_with_pefile(binary_path: str) -> Optional[List[float]]:
        """Extract PE features using pefile library."""
        import pefile
        
        try:
            pe = pefile.PE(binary_path)
            features = []
            
            # DOS Header Features (2 features)
            features.append(float(pe.DOS_HEADER.e_magic))  # MZ signature
            features.append(float(pe.DOS_HEADER.e_lfanew))  # PE offset
            
            # File Header Features (4 features)
            features.append(float(pe.FILE_HEADER.Machine))  # Target machine
            features.append(float(pe.FILE_HEADER.NumberOfSections))  # Number of sections
            features.append(float(pe.FILE_HEADER.TimeDateStamp))  # Compile timestamp
            features.append(float(pe.FILE_HEADER.PointerToSymbolTable))  # Symbol table pointer
            
            # Optional Header Features (8 features)
            opt_header = pe.OPTIONAL_HEADER
            features.append(float(opt_header.Magic))  # 32-bit or 64-bit
            features.append(float(opt_header.AddressOfEntryPoint))  # Entry point
            features.append(float(opt_header.BaseOfCode))  # Code base
            features.append(float(opt_header.BaseOfData if hasattr(opt_header, 'BaseOfData') else 0))  # Data base
            features.append(float(opt_header.ImageBase))  # Image base address
            features.append(float(opt_header.SectionAlignment))  # Section alignment
            features.append(float(opt_header.FileAlignment))  # File alignment
            features.append(float(opt_header.MajorOperatingSystemVersion))  # OS version
            
            # Section Features (7 features)
            num_executable_sections = sum(1 for s in pe.sections 
                                        if s.Characteristics & 0x20000000)  # Executable flag
            features.append(float(num_executable_sections))
            
            writable_sections = sum(1 for s in pe.sections 
                                   if s.Characteristics & 0x80000000)  # Writable flag
            features.append(float(writable_sections))
            
            total_section_size = sum(s.VirtualSize for s in pe.sections)
            features.append(float(total_section_size))
            
            # Section entropy features
            entropies = []
            for section in pe.sections:
                try:
                    entropy = PEHeaderExtractor._calculate_entropy(
                        section.get_data()
                    )
                    entropies.append(entropy)
                except:
                    entropies.append(0.0)
            
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
            features.append(float(avg_entropy))
            
            max_entropy = max(entropies) if entropies else 0.0
            features.append(float(max_entropy))
            
            # Suspicious characteristics
            suspicious_flags = 0
            for section in pe.sections:
                # Count sections with unusual combinations
                if (section.Characteristics & 0x60000000) == 0x60000000:  # Both readable and writable
                    suspicious_flags += 1
            features.append(float(suspicious_flags))
            
            # Padding between sections
            total_padding = 0
            sorted_sections = sorted(pe.sections, key=lambda x: x.PointerToRawData)
            for i in range(len(sorted_sections) - 1):
                curr_section = sorted_sections[i]
                next_section = sorted_sections[i + 1]
                padding = next_section.PointerToRawData - (
                    curr_section.PointerToRawData + curr_section.SizeOfRawData
                )
                total_padding += max(0, padding)
            features.append(float(total_padding))
            
            # Import table features (2 features)
            num_imports = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                num_imports = sum(len(dll.imports) for dll in pe.DIRECTORY_ENTRY_IMPORT)
            features.append(float(num_imports))
            
            # Export table features
            num_exports = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            features.append(float(num_exports))
            
            # Resource section size
            resource_size = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_size = pe.DIRECTORY_ENTRY_RESOURCE.struct.Size
            features.append(float(resource_size))
            
            # Pad to exactly 25 features if needed
            while len(features) < PEHeaderExtractor.PE_FEATURES_COUNT:
                features.append(0.0)
            
            # Truncate if too many
            features = features[:PEHeaderExtractor.PE_FEATURES_COUNT]
            
            logger.info(f"Extracted {len(features)} PE features from {binary_path}")
            return features
            
        except Exception as e:
            logger.error(f"pefile extraction failed: {e}")
            raise
    
    @staticmethod
    def _extract_fallback_features(binary_path: str) -> List[float]:
        """
        Fallback PE feature extraction without pefile.
        Reads raw PE headers from binary.
        """
        features = [0.0] * PEHeaderExtractor.PE_FEATURES_COUNT
        
        try:
            with open(binary_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64:
                    return features
                
                # MZ signature
                features[0] = struct.unpack('<H', dos_header[0:2])[0]  # "MZ"
                # PE offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                features[1] = float(pe_offset)
                
                # Read PE header
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return features
                
                # File header (20 bytes)
                file_header = f.read(20)
                if len(file_header) < 20:
                    return features
                
                features[2] = struct.unpack('<H', file_header[0:2])[0]  # Machine
                features[3] = struct.unpack('<H', file_header[2:4])[0]  # NumberOfSections
                features[4] = float(struct.unpack('<I', file_header[4:8])[0])  # TimeDateStamp
                
                # Optional header info
                opt_header_size = struct.unpack('<H', file_header[16:18])[0]
                opt_header = f.read(opt_header_size)
                
                if len(opt_header) >= 4:
                    features[6] = struct.unpack('<H', opt_header[0:2])[0]  # Magic
                    features[7] = float(struct.unpack('<I', opt_header[16:20])[0])  # AddressOfEntryPoint
                
                # File size
                file_size = os.path.getsize(binary_path)
                features[5] = float(file_size)
                
                # Calculate simple entropy from file header
                header_data = dos_header + f.read(256)
                entropy = PEHeaderExtractor._calculate_entropy(header_data[:256])
                features[13] = entropy
                
            logger.info(f"Fallback extraction: {len(features)} features from {binary_path}")
            return features
            
        except Exception as e:
            logger.error(f"Fallback extraction error: {e}")
            return features
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        import math
        
        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i])) / len(data)
            if freq > 0:
                entropy -= freq * math.log2(freq)
        
        return entropy


class PEHeaderDetectionService:
    """
    Service for detecting ransomware using PE header analysis.
    Layer 2 of 3-layer detection system.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize PE header detection service.
        
        Args:
            model_path: Optional path to the trained model
        """
        self.logger = logger
        self.model_path = model_path or "backend/ml/models/pe_header_ransomware_model.pkl"
        self.model_info_path = "backend/ml/models/pe_header_ransomware_model_info.json"
        self.model = None
        self.model_info = None
        self.extractor = PEHeaderExtractor()
        self._load_model()
        self._load_model_info()
    
    def _load_model(self) -> None:
        """Load the trained PE header model."""
        paths_to_try = [
            self.model_path,
            os.path.join(os.path.dirname(__file__), 'models', 'pe_header_ransomware_model.pkl'),
            os.path.join('backend', 'ml', 'models', 'pe_header_ransomware_model.pkl'),
            os.path.join('ml', 'models', 'pe_header_ransomware_model.pkl'),
        ]
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    self.model = joblib.load(path)
                    self.logger.info(f"✅ PE header model loaded from {path}")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load model from {path}: {e}")
        
        self.logger.warning("⚠️ PE header model file not found. Running in prediction-only mode.")
    
    def _load_model_info(self) -> None:
        """Load model metadata."""
        paths_to_try = [
            self.model_info_path,
            os.path.join(os.path.dirname(__file__), 'models', 'pe_header_ransomware_model_info.json'),
            os.path.join('backend', 'ml', 'models', 'pe_header_ransomware_model_info.json'),
            os.path.join('ml', 'models', 'pe_header_ransomware_model_info.json'),
        ]
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        self.model_info = json.load(f)
                    self.logger.info("✅ PE header model info loaded")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load model info from {path}: {e}")
    
    def is_model_loaded(self) -> bool:
        """Check if model is ready."""
        return self.model is not None
    
    def predict(self, binary_path: str) -> Dict[str, Any]:
        """
        Predict if a binary is ransomware based on PE headers.
        
        Args:
            binary_path: Path to the executable file
        
        Returns:
            Dictionary with prediction results
        """
        result = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'binary_path': binary_path,
            'is_ransomware': False,
            'confidence': 0.0,
            'model_loaded': self.is_model_loaded(),
            'error': None,
        }
        
        try:
            # Check if file exists
            if not os.path.exists(binary_path):
                result['error'] = f"File not found: {binary_path}"
                return result
            
            # Extract features
            features = self.extractor.extract_features(binary_path)
            if features is None:
                result['error'] = "Failed to extract PE features"
                return result
            
            result['features_extracted'] = len(features)
            
            # Make prediction if model is loaded
            if self.model:
                try:
                    prediction = self.model.predict([features])
                    probabilities = self.model.predict_proba([features])
                    
                    is_ransomware = bool(prediction[0] == 1)
                    confidence = float(probabilities[0][1])  # Probability of ransomware
                    
                    result['is_ransomware'] = is_ransomware
                    result['confidence'] = round(confidence, 4)
                    result['prediction_class'] = 1 if is_ransomware else 0
                    
                except Exception as e:
                    result['error'] = f"Prediction error: {str(e)}"
            else:
                result['warning'] = "Model not loaded - cannot make prediction"
        
        except Exception as e:
            self.logger.error(f"Error in predict: {e}")
            result['error'] = str(e)
        
        return result
    
    def get_model_info(self) -> Optional[Dict[str, Any]]:
        """Get model metadata and metrics."""
        return self.model_info
    
    def get_features_info(self) -> Dict[str, Any]:
        """Get information about PE features used."""
        return {
            'total_features': PEHeaderExtractor.PE_FEATURES_COUNT,
            'feature_categories': [
                'DOS Header (2)',
                'File Header (4)',
                'Optional Header (8)',
                'Section Info (7)',
                'Import/Export (2)',
                'Resource Info (1)',
                'Padding/Suspicious (1)',
            ]
        }


# Singleton instance
_pe_service = None


def get_pe_detection_service() -> PEHeaderDetectionService:
    """Get or create the PE header detection service singleton."""
    global _pe_service
    if _pe_service is None:
        _pe_service = PEHeaderDetectionService()
    return _pe_service


def predict_binary(binary_path: str) -> Dict[str, Any]:
    """Quick prediction helper function."""
    service = get_pe_detection_service()
    return service.predict(binary_path)

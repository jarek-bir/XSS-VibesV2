"""Modern payload management module."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from dataclasses import asdict

from .models import Payload, VulnerabilityLevel
from .encoding_engine import (
    advanced_encoder,
    context_encoder,
    EncodingType,
    EncodingResult,
    generate_evasion_variants,
    encode_for_context,
)


logger = logging.getLogger("xss_vibes.payloads")


class PayloadManager:
    """Manages XSS payloads and their attributes."""

    DANGEROUS_CHARACTERS = {
        ">",
        "'",
        '"',
        "<",
        "/",
        ";",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "=",
        "&",
    }

    def __init__(
        self,
        payload_file: Path = Path(__file__).parent / "data" / "payloads.json",
        waf_payload_file: Path = Path(__file__).parent / "data" / "waf_payloads.json",
    ):
        """
        Initialize payload manager.

        Args:
            payload_file: Path to the JSON file containing standard payloads
            waf_payload_file: Path to the JSON file containing WAF-specific payloads
        """
        self.payload_file = payload_file
        self.waf_payload_file = waf_payload_file
        self._payloads: List[Payload] = []
        self._waf_payloads: List[Payload] = []
        self._load_payloads()
        self._load_waf_payloads()

    def _load_payloads(self) -> None:
        """Load payloads from JSON file."""
        if not self.payload_file.exists():
            logger.warning(
                f"Payload file {self.payload_file} not found, creating empty payload list"
            )
            self._payloads = []
            return

        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                payload_data = json.load(f)

            self._payloads = []
            for data in payload_data:
                payload = Payload(
                    content=data.get("Payload", ""),
                    attributes=data.get("Attribute", []),
                    waf=data.get("waf"),
                    count=data.get("count", 0),
                    description=data.get("description"),
                    level=VulnerabilityLevel(data.get("level", "medium")),
                )
                self._payloads.append(payload)

            logger.info(
                f"Loaded {len(self._payloads)} payloads from {self.payload_file}"
            )

        except Exception as e:
            logger.error(f"Error loading payloads: {e}")
            self._payloads = []

    def _load_waf_payloads(self) -> None:
        """Load WAF-specific payloads from JSON file."""
        if not self.waf_payload_file.exists():
            logger.warning(f"WAF payload file {self.waf_payload_file} not found")
            self._waf_payloads = []
            return

        try:
            with open(self.waf_payload_file, "r", encoding="utf-8") as f:
                payload_data = json.load(f)

            self._waf_payloads = []
            for data in payload_data:
                payload = Payload(
                    content=data.get("Payload", ""),
                    attributes=data.get("Attribute", []),
                    waf=data.get("waf"),
                    count=data.get("count", 0),
                    description=data.get("description"),
                    level=VulnerabilityLevel(data.get("level", "medium")),
                )
                self._waf_payloads.append(payload)

            logger.info(f"Loaded {len(self._waf_payloads)} WAF-specific payloads")

        except Exception as e:
            logger.error(f"Error loading WAF payloads: {e}")
            self._waf_payloads = []

    def save_payloads(self) -> None:
        """Save payloads to JSON file."""
        try:
            payload_data = []
            for payload in self._payloads:
                data = {
                    "Payload": payload.content,
                    "Attribute": payload.attributes,
                    "waf": payload.waf,
                    "count": payload.count,
                    "description": payload.description,
                    "level": payload.level.value,
                }
                payload_data.append(data)

            with open(self.payload_file, "w", encoding="utf-8") as f:
                json.dump(payload_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved {len(self._payloads)} payloads to {self.payload_file}")

        except Exception as e:
            logger.error(f"Error saving payloads: {e}")

    def add_payload(
        self,
        content: str,
        waf: Optional[str] = None,
        description: Optional[str] = None,
        level: VulnerabilityLevel = VulnerabilityLevel.MEDIUM,
    ) -> Payload:
        """
        Add a new payload.

        Args:
            content: The payload content
            waf: WAF type this payload is designed for
            description: Description of the payload
            level: Vulnerability level

        Returns:
            The created Payload object
        """
        payload = Payload(
            content=content, waf=waf, description=description, level=level
        )

        self._payloads.append(payload)
        logger.info(f"Added new payload: {content[:50]}...")

        return payload

    def add_payloads_from_file(self, file_path: Path, waf: Optional[str] = None) -> int:
        """
        Add payloads from a text file.

        Args:
            file_path: Path to file containing payloads (one per line)
            waf: WAF type for all payloads in file

        Returns:
            Number of payloads added
        """
        if not file_path.exists():
            logger.error(f"Payload file {file_path} not found")
            return 0

        added_count = 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.add_payload(line, waf=waf)
                        added_count += 1

            logger.info(f"Added {added_count} payloads from {file_path}")

        except Exception as e:
            logger.error(f"Error reading payload file {file_path}: {e}")

        return added_count

    def get_filtered_payloads(
        self,
        reflected_chars: Set[str],
        waf: Optional[str] = None,
        min_match_ratio: float = 0.5,
    ) -> List[Payload]:
        """
        Get payloads filtered by reflected characters and WAF.

        Args:
            reflected_chars: Set of characters that are reflected in responses
            waf: WAF type to filter for (None for general payloads)
            min_match_ratio: Minimum ratio of payload chars that must be reflected

        Returns:
            List of filtered payloads sorted by effectiveness
        """
        if not reflected_chars:
            return []

        # Filter by WAF from both standard and WAF-specific payloads
        if waf:
            # Try WAF-specific payloads first
            waf_specific = [
                p for p in self._waf_payloads if p.waf and waf.lower() in p.waf.lower()
            ]
            standard_waf = [
                p for p in self._payloads if p.waf and waf.lower() in p.waf.lower()
            ]
            candidate_payloads = waf_specific + standard_waf

            if not candidate_payloads:
                logger.warning(f"No payloads found for WAF: {waf}")
                return []
        else:
            candidate_payloads = [p for p in self._payloads if not p.waf]

        # Score payloads based on character matches
        scored_payloads = []
        for payload in candidate_payloads:
            if not payload.attributes:
                continue

            # Calculate match ratio
            payload_chars = set(payload.attributes)
            matched_chars = payload_chars.intersection(reflected_chars)
            match_ratio = (
                len(matched_chars) / len(payload_chars) if payload_chars else 0
            )

            if match_ratio >= min_match_ratio:
                # Update count for sorting
                payload.count = len(matched_chars)
                scored_payloads.append(payload)

        # Sort by effectiveness (perfect matches first, then by character count)
        def sort_key(p):
            perfect_match = len(set(p.attributes)) == len(
                set(p.attributes).intersection(reflected_chars)
            )
            return (perfect_match, p.count, len(p.content))

        scored_payloads.sort(key=sort_key, reverse=True)

        if scored_payloads:
            logger.info(f"Found {len(scored_payloads)} suitable payloads")
            if scored_payloads[0].count == len(set(scored_payloads[0].attributes)):
                logger.info("Found perfect payload matches!")

        return scored_payloads

    def get_dangerous_characters(self) -> Set[str]:
        """Get the set of dangerous characters used for testing."""
        return self.DANGEROUS_CHARACTERS.copy()

    @property
    def payload_count(self) -> int:
        """Get the total number of standard payloads."""
        return len(self._payloads)

    @property
    def waf_payload_count(self) -> int:
        """Get the total number of WAF-specific payloads."""
        return len(self._waf_payloads)

    @property
    def total_payload_count(self) -> int:
        """Get the total number of all payloads."""
        return len(self._payloads) + len(self._waf_payloads)

    def get_waf_types(self) -> List[str]:
        """Get list of all WAF types in payloads."""
        waf_types = set()
        for payload in self._payloads + self._waf_payloads:
            if payload.waf:
                waf_types.add(payload.waf)
        return sorted(list(waf_types))

    def get_payloads_by_level(
        self, level: VulnerabilityLevel, include_waf: bool = True
    ) -> List[Payload]:
        """Get payloads filtered by vulnerability level."""
        payloads = self._payloads.copy()
        if include_waf:
            payloads.extend(self._waf_payloads)
        return [p for p in payloads if p.level == level]

    def get_all_payloads_combined(
        self, waf_type: Optional[str] = None, level: Optional[VulnerabilityLevel] = None
    ) -> List[Payload]:
        """
        Get all payloads (standard + WAF-specific) with optional filtering.

        Args:
            waf_type: Filter by WAF type
            level: Filter by vulnerability level

        Returns:
            Combined list of filtered payloads
        """
        all_payloads = self._payloads + self._waf_payloads

        if waf_type:
            all_payloads = [p for p in all_payloads if p.waf == waf_type]

        if level:
            all_payloads = [p for p in all_payloads if p.level == level]

        return all_payloads

    def generate_encoded_payloads(
        self,
        base_payloads: Optional[List[Payload]] = None,
        encoding_types: Optional[List[EncodingType]] = None,
        max_variants: int = 5,
    ) -> List[Payload]:
        """
        Generate encoded variants of payloads for advanced evasion.

        Args:
            base_payloads: Base payloads to encode (defaults to all loaded payloads)
            encoding_types: Specific encoding types to use (defaults to automatic selection)
            max_variants: Maximum variants per payload

        Returns:
            List of new Payload objects with encoded content
        """
        if base_payloads is None:
            base_payloads = self.get_all_payloads_combined()

        encoded_payloads = []

        for payload in base_payloads:
            if encoding_types:
                # Use specific encoding types
                for encoding_type in encoding_types[:max_variants]:
                    try:
                        result = advanced_encoder.encode_payload(
                            payload.content, encoding_type
                        )
                        encoded_payload = Payload(
                            content=result.encoded,
                            level=payload.level,
                            description=f"{payload.description} [Encoded: {result.description}]",
                            waf=payload.waf,
                            context=payload.context,
                            bypass_potential=min(
                                10,
                                payload.bypass_potential + result.waf_bypass_potential,
                            ),
                        )
                        encoded_payloads.append(encoded_payload)
                    except Exception as e:
                        logger.warning(
                            f"Failed to encode payload '{payload.content[:50]}...': {e}"
                        )
            else:
                # Generate automatic variants
                try:
                    variants = generate_evasion_variants(payload.content, max_variants)
                    for variant in variants:
                        encoded_payload = Payload(
                            content=variant.encoded,
                            level=payload.level,
                            description=f"{payload.description} [Encoded: {variant.description}]",
                            waf=payload.waf,
                            context=payload.context,
                            bypass_potential=min(
                                10,
                                payload.bypass_potential + variant.waf_bypass_potential,
                            ),
                        )
                        encoded_payloads.append(encoded_payload)
                except Exception as e:
                    logger.warning(
                        f"Failed to generate variants for payload '{payload.content[:50]}...': {e}"
                    )

        logger.info(f"Generated {len(encoded_payloads)} encoded payload variants")
        return encoded_payloads

    def generate_context_aware_payloads(
        self,
        url: str,
        parameter: str,
        base_payloads: Optional[List[Payload]] = None,
        max_variants: int = 5,
    ) -> List[Payload]:
        """
        Generate context-aware encoded payloads for specific injection context.

        Args:
            url: Target URL for context detection
            parameter: Parameter name for context detection
            base_payloads: Base payloads to encode
            max_variants: Maximum variants per payload

        Returns:
            List of context-aware encoded payloads
        """
        if base_payloads is None:
            base_payloads = self.get_all_payloads_combined()

        # Detect injection context
        context = context_encoder.detect_context(url, parameter)
        logger.info(f"Detected injection context: {context} for {url}#{parameter}")

        encoded_payloads = []

        for payload in base_payloads:
            try:
                variants = encode_for_context(payload.content, context, max_variants)
                for variant in variants:
                    encoded_payload = Payload(
                        content=variant.encoded,
                        level=payload.level,
                        description=f"{payload.description} [Context: {context}, {variant.description}]",
                        waf=payload.waf,
                        context=context,
                        bypass_potential=min(
                            10, payload.bypass_potential + variant.waf_bypass_potential
                        ),
                    )
                    encoded_payloads.append(encoded_payload)
            except Exception as e:
                logger.warning(f"Failed to generate context-aware variants: {e}")

        logger.info(
            f"Generated {len(encoded_payloads)} context-aware payload variants for {context}"
        )
        return encoded_payloads

    def get_high_evasion_payloads(
        self,
        waf_type: Optional[str] = None,
        min_bypass_potential: int = 7,
        max_count: int = 50,
    ) -> List[Payload]:
        """
        Get high-evasion payloads with advanced encoding techniques.

        Args:
            waf_type: Target WAF type
            min_bypass_potential: Minimum bypass potential score
            max_count: Maximum number of payloads to return

        Returns:
            List of high-evasion payloads
        """
        # Get base payloads
        base_payloads = self.get_all_payloads_combined(waf_type=waf_type)

        # Filter by bypass potential
        high_potential_payloads = [
            p for p in base_payloads if p.bypass_potential >= min_bypass_potential
        ]

        # Generate encoded variants for top payloads
        top_payloads = high_potential_payloads[: max_count // 3]  # Use 1/3 for encoding
        encoded_variants = self.generate_encoded_payloads(
            base_payloads=top_payloads,
            encoding_types=[
                EncodingType.UTF7,
                EncodingType.FROMCHARCODE,
                EncodingType.BASE64,
                EncodingType.UNICODE,
                EncodingType.DOUBLE_URL,
            ],
            max_variants=3,
        )

        # Combine and sort by bypass potential
        all_evasion_payloads = high_potential_payloads + encoded_variants
        all_evasion_payloads.sort(key=lambda p: p.bypass_potential, reverse=True)

        return all_evasion_payloads[:max_count]

    def analyze_payload_evasion_potential(self, payload: str) -> Dict[str, Any]:
        """
        Analyze a payload's evasion potential across different encoding techniques.

        Args:
            payload: Payload string to analyze

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            "original_payload": payload,
            "character_analysis": self._analyze_dangerous_characters(payload),
            "encoding_variants": [],
            "best_encodings": [],
            "waf_bypass_score": 0,
        }

        # Generate variants for all encoding types
        variants = []
        for encoding_type in EncodingType:
            try:
                result = advanced_encoder.encode_payload(payload, encoding_type)
                variants.append(result)
                analysis["encoding_variants"].append(
                    {
                        "encoding": encoding_type.value,
                        "encoded_payload": result.encoded,
                        "complexity": result.complexity,
                        "bypass_potential": result.waf_bypass_potential,
                        "description": result.description,
                    }
                )
            except Exception as e:
                logger.debug(f"Failed encoding {encoding_type}: {e}")

        # Find best encodings
        variants.sort(key=lambda x: x.waf_bypass_potential, reverse=True)
        analysis["best_encodings"] = [
            {
                "encoding": v.encoding_type.value,
                "bypass_potential": v.waf_bypass_potential,
                "description": v.description,
            }
            for v in variants[:5]
        ]

        # Calculate overall bypass score
        if variants:
            analysis["waf_bypass_score"] = max(v.waf_bypass_potential for v in variants)

        return analysis

    def _analyze_dangerous_characters(self, payload: str) -> Dict[str, Any]:
        """Analyze dangerous characters in payload."""
        dangerous_found = [
            char for char in self.DANGEROUS_CHARACTERS if char in payload
        ]

        return {
            "dangerous_characters": dangerous_found,
            "danger_count": len(dangerous_found),
            "danger_score": len(dangerous_found) / len(self.DANGEROUS_CHARACTERS) * 10,
            "requires_encoding": len(dangerous_found) > 0,
        }

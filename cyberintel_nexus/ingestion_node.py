"""
Ingestion Node Module for CyberIntel Nexus.
Handles the ingestion of raw threat intelligence from local files or MCP servers,
and uses Gemini via the Agent Development Kit (ADK) to extract and validate indicators.
"""
from __future__ import annotations

import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Literal, TypedDict

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    try:
        from cyberintel_nexus.state_engine import AgentState, Indicator
    except ImportError:
        from state_engine import AgentState, Indicator

logger = logging.getLogger("CyberIntelNexus.IngestionNode")

# Try to import Google ADK Agent
try:
    from google.adk.agents import Agent
    ADK_AVAILABLE = True
except ImportError:
    ADK_AVAILABLE = False
    
    class Agent:
        """Mock ADK Agent for offline execution environments."""
        def __init__(self, name: str, model: str, instruction: str, response_schema: Optional[Any] = None):
            self.name = name
            self.model = model
            self.instruction = instruction
            self.response_schema = response_schema

        def run(self, input_text: str) -> str:
            # Emulated Gemini extraction logic
            logger.info("Executing Mock ADK Gemini Agent run...")
            
            # Simple regex-based extraction to simulate LLM performance
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', input_text)
            domains = re.findall(r'\b(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}\b', input_text)
            hashes = re.findall(r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b', input_text)
            
            indicators = []
            for ip in set(ips):
                indicators.append({
                    "type": "ip",
                    "value": ip,
                    "context": f"Identified IP {ip} in unstructured threat report.",
                    "confidence": 0.90
                })
            for domain in set(domains):
                if not domain.replace('.', '').isdigit() and domain.lower() not in ["github.com", "google.com"]:
                    indicators.append({
                        "type": "domain",
                        "value": domain,
                        "context": f"Identified malicious domain {domain} in threat advisory.",
                        "confidence": 0.85
                    })
            for h in set(hashes):
                h_type = "md5" if len(h) == 32 else ("sha1" if len(h) == 40 else "sha256")
                indicators.append({
                    "type": "hash",
                    "value": h,
                    "context": f"Identified threat payload {h_type.upper()} hash: {h}.",
                    "confidence": 0.95
                })
                
            return json.dumps({"indicators": indicators})


# ==========================================
# MCP Client & Ingestion Utilities
# ==========================================

class MockMCPClient:
    """Mock client for Model Context Protocol (MCP) host servers."""
    def __init__(self, server_uri: str = "mcp://cyberintel-hub"):
        self.server_uri = server_uri

    def read_resource(self, resource_path: str) -> str:
        """Simulates reading unstructured documents from an MCP resource path."""
        logger.info(f"MCP Client: Reading resource '{resource_path}' from {self.server_uri}")
        
        if "apt-feed" in resource_path:
            return (
                "# Threat Alert: APT-35 Campaign Activity\n\n"
                "A recent campaign by APT-35 targeting defense contractors has been uncovered.\n"
                "The campaign utilizes C2 server 198.51.100.99 for hosting payloads.\n"
                "A second payload connects back to C2 domain update-service-check.org.\n"
                "We observed delivery of a dropper with SHA-256: 857e5b1234abcd092123efcd45678ab2e456cde91f09231872134567abcd1234."
            )
        elif "clean-feed" in resource_path:
            return "No suspicious indicator parameters or malicious files detected in logs today."
        else:
            raise ValueError(f"MCP resource path '{resource_path}' was not found.")


def read_local_file(filepath: str) -> str:
    """Reads raw threat intelligence text or markdown from a local file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Local threat feed file not found at: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


# ==========================================
# ADK Gemini Agent Extraction & Validation
# ==========================================

def extract_indicators_with_adk(text: str) -> List[Dict[str, Any]]:
    """
    Invokes Gemini via the Agent Development Kit (ADK) to extract threat indicators.
    """
    logger.info("Initializing ADK Gemini extraction agent...")
    
    instruction = (
        "You are an AI Threat Intelligence Analyst. Your task is to analyze unstructured documents "
        "and extract host and network indicators of compromise (IOCs). "
        "Strictly identify:\n"
        "1. IP Addresses (type: 'ip')\n"
        "2. Domain Names (type: 'domain')\n"
        "3. Cryptographic Hashes (type: 'hash' - MD5, SHA-1, SHA-256)\n\n"
        "Return the output as a valid JSON object with the structure:\n"
        "{\n"
        "  \"indicators\": [\n"
        "    {\"type\": \"ip\"|\"domain\"|\"hash\", \"value\": \"...\", \"context\": \"...\", \"confidence\": 0.0-1.0}\n"
        "  ]\n"
        "}\n"
        "Do not include code fences or markdown blocks in your response."
    )
    
    # Initialize the ADK Agent
    extractor = Agent(
        name="ADK_Indicator_Extractor",
        model="gemini-2.5-flash",
        instruction=instruction
    )
    
    try:
        raw_response = extractor.run(text)
        cleaned_response = raw_response.strip()
        
        # Clean markdown codeblocks
        if cleaned_response.startswith("```"):
            lines = cleaned_response.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned_response = "\n".join(lines).strip()
            
        data = json.loads(cleaned_response)
        return data.get("indicators", [])
    except Exception as e:
        logger.error(f"ADK Gemini extraction failed: {e}. Falling back to regex extraction.")
        return fallback_regex_extractor(text)


def fallback_regex_extractor(text: str) -> List[Dict[str, Any]]:
    """Emergency regex parser to ensure graceful degradation if LLM call fails."""
    logger.info("Executing fallback regex extractor...")
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}\b', text)
    hashes = re.findall(r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b', text)
    
    indicators = []
    for ip in set(ips):
        if all(0 <= int(part) <= 255 for part in ip.split('.')):
            indicators.append({"type": "ip", "value": ip, "context": "Extracted via local fallback regex.", "confidence": 0.80})
    for domain in set(domains):
        if not domain.replace('.', '').isdigit() and domain.lower() not in ["github.com", "google.com"]:
            indicators.append({"type": "domain", "value": domain, "context": "Extracted via local fallback regex.", "confidence": 0.70})
    for h in set(hashes):
        indicators.append({"type": "hash", "value": h, "context": "Extracted via local fallback regex.", "confidence": 0.85})
    return indicators


def sanitize_and_validate_indicators(extracted: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Validates the schema, defangs values, and formats indicators to match AgentState requirements.
    """
    logger.info("Beginning rigorous data sanitation and schema validation checks...")
    validated_list = []
    
    for idx, item in enumerate(extracted):
        try:
            # 1. Schema check: Required fields
            if "type" not in item or "value" not in item:
                logger.warning(f"Item #{idx} failed schema check: Missing 'type' or 'value'.")
                continue
                
            ind_type = str(item["type"]).strip().lower()
            ind_value = str(item["value"]).strip()
            
            # 2. Defanging and sanitation
            ind_value = ind_value.replace("[.]", ".").replace("hxxp", "http").replace("[@", "@")
            
            # Extract domain from URL format if present
            if ind_type == "domain":
                if "://" in ind_value:
                    ind_value = ind_value.split("://", 1)[1]
                if "/" in ind_value:
                    ind_value = ind_value.split("/", 1)[0]
                if ":" in ind_value:
                    ind_value = ind_value.split(":", 1)[0]
            
            # 3. Type-specific verification
            if ind_type == "ip":
                # Ensure valid IPv4 boundaries
                octets = ind_value.split('.')
                if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                    logger.warning(f"IP validation failed: '{ind_value}'")
                    continue
            elif ind_type == "domain":
                # Ensure valid domain formatting
                if len(ind_value) < 4 or "." not in ind_value or re.search(r'[^a-zA-Z0-9_.-]', ind_value):
                    logger.warning(f"Domain validation failed: '{ind_value}'")
                    continue
            elif ind_type == "hash":
                # Ensure valid MD5/SHA-1/SHA-256 formatting
                if len(ind_value) not in [32, 40, 64] or not all(c in "0123456789abcdefABCDEF" for c in ind_value):
                    logger.warning(f"Cryptographic hash validation failed: '{ind_value}'")
                    continue
            else:
                logger.warning(f"Unknown indicator type '{ind_type}'. Coercing to 'other'.")
                ind_type = "other"
                
            # 4. Map directly to Indicator TypedDict schema
            sanitized = {
                "id": str(uuid.uuid4()),
                "type": ind_type,
                "value": ind_value,
                "context": str(item.get("context", "Extracted and sanitized threat indicator.")).strip(),
                "confidence": float(item.get("confidence", 0.75))
            }
            validated_list.append(sanitized)
            
        except Exception as e:
            logger.error(f"Failed to process and validate indicator index {idx}: {e}")
            continue
            
    return validated_list


# ==========================================
# LangGraph Node Implementations
# ==========================================

def ingest_threat_intel_node(state: "AgentState") -> Dict[str, Any]:
    """
    Ingestion node. Handles files or MCP server integration.
    Looks for filepaths or MCP URIs in metadata to perform ingestion,
    or falls back to raw_threat_intel string directly.
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, "ingest")
    logger.info(f"[{new_state['session_id']}] Node: Ingest Threat Intel (Extended)")
    
    raw_text = state.get("raw_threat_intel", "")
    metadata = state.get("metadata", {})
    
    # 1. Attempt MCP Ingestion if URI is provided
    mcp_uri = metadata.get("mcp_uri")
    mcp_resource = metadata.get("mcp_resource_path")
    if mcp_uri and mcp_resource:
        try:
            mcp_client = MockMCPClient(server_uri=mcp_uri)
            raw_text = mcp_client.read_resource(mcp_resource)
            logger.info("Successfully ingested raw report from MCP host.")
        except Exception as e:
            logger.error(f"Failed to ingest from MCP: {e}")
            
    # 2. Attempt Local File Ingestion if filepath is provided
    filepath = metadata.get("local_filepath")
    if filepath:
        try:
            raw_text = read_local_file(filepath)
            logger.info(f"Successfully ingested raw report from local file: {filepath}")
        except Exception as e:
            logger.error(f"Failed to ingest from local file: {e}")
            
    status = "Threat intelligence document ingested successfully."
    return {
        "current_phase": "ingest",
        "raw_threat_intel": raw_text,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }


def parse_threat_intel_node(state: "AgentState") -> Dict[str, Any]:
    """
    Parsing node. Integrates Gemini via the ADK, sanitizes and validates
    structured indicators, and maps them to state indicators.
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, "parse")
    logger.info(f"[{new_state['session_id']}] Node: Parse Structured Indicators (Extended)")
    
    raw_text = state.get("raw_threat_intel", "")
    if not raw_text:
        # Route immediately to error state by setting indicators to empty
        logger.error("No threat intelligence text available to parse.")
        return {
            "current_phase": "parse",
            "indicators": [],
            "execution_history": new_state["execution_history"],
            "retry_counts": new_state["retry_counts"],
            "status_message": "Parsing failed: raw_threat_intel is empty."
        }
        
    # 1. Parse via ADK Gemini Agent
    extracted = extract_indicators_with_adk(raw_text)
    
    # 2. Sanitize and Validate
    validated_indicators = sanitize_and_validate_indicators(extracted)
    
    # 3. Update status message
    if not validated_indicators:
        status = "Sanitation failed: Zero valid indicators could be extracted from feed."
        logger.warning(status)
    else:
        status = f"Parsed and validated {len(validated_indicators)} structured indicators."
        logger.info(status)
        
    return {
        "current_phase": "parse",
        "indicators": validated_indicators,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }

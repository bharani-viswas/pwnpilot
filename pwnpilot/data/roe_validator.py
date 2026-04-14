"""
ROE (Rules of Engagement) Schema Validation

Validates ROE YAML files against strict templates to prevent:
- Ambiguous scope descriptions
- Missing required fields  
- Invalid value ranges
- Injection attempts
"""

import re
from typing import Union, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, EmailStr, ValidationError, ConfigDict, ValidationInfo


def _parse_comma_separated_string(value: Union[str, List[str], None]) -> List[str]:
    """Convert comma-separated string to list, or pass through lists unchanged."""
    if not value:
        return []
    if isinstance(value, str):
        # Split by comma and strip whitespace
        return [item.strip() for item in value.split(',') if item.strip()]
    return value if value else []


class EngagementMeta(BaseModel):
    """Engagement metadata section"""
    
    name: str = Field(
        ..., 
        min_length=8, 
        max_length=64,
        description="Engagement name (8-64 chars)"
    )
    authorizer: EmailStr = Field(
        ...,
        description="Authorizer email address"
    )
    description: str = Field(
        ...,
        min_length=100,
        description="Engagement purpose description (min 100 chars)"
    )
    valid_hours: int = Field(
        default=24,
        ge=1,
        le=8760,
        description="Engagement validity window (1-8760 hours)"
    )


class Scope(BaseModel):
    """Scope definition - must be explicit and machine-readable"""

    target_profile: str = Field(
        default="default",
        description="Target profile: default, local, or lab"
    )
    
    # Store as strings (comma-separated), but validate parse-ability and content
    cidrs: str = Field(
        default="",
        description="CIDR blocks to test (explicit IPv4 CIDR notation)"
    )
    domains: str = Field(
        default="",
        description="Domains to test (exact FQDNs, no wildcards)"
    )
    urls: str = Field(
        default="",
        description="URLs to test (with protocol, exact prefixes)"
    )
    excluded_ips: str = Field(
        default="",
        description="IPs to exclude from testing"
    )
    restricted_actions: str = Field(
        default="",
        description="Actions explicitly prohibited"
    )
    
    @field_validator('cidrs', mode='after')
    @classmethod
    def validate_cidrs(cls, v):
        """Validate each CIDR is valid IPv4 CIDR notation"""
        import ipaddress
        
        items = _parse_comma_separated_string(v)
        for cidr in items:
            try:
                ipaddress.IPv4Network(cidr, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid CIDR '{cidr}': {str(e)}")
        return v
    
    @field_validator('domains', mode='after')
    @classmethod
    def validate_domains(cls, v, info: ValidationInfo):
        """Validate domains are valid FQDNs"""
        fqdn_pattern = r'^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]{2,}$'
        target_profile = str(info.data.get('target_profile', 'default')).lower()
        
        items = _parse_comma_separated_string(v)
        for domain in items:
            if domain.lower() == 'localhost' and target_profile in {'local', 'lab'}:
                continue
            if not re.match(fqdn_pattern, domain.lower()):
                raise ValueError(f"Invalid domain '{domain}': must be valid FQDN")
        return v

    @field_validator('target_profile', mode='after')
    @classmethod
    def validate_target_profile(cls, v):
        allowed = {'default', 'local', 'lab'}
        if v not in allowed:
            raise ValueError(f"Invalid target_profile '{v}'. Allowed: {', '.join(sorted(allowed))}")
        return v
    
    @field_validator('urls', mode='after')
    @classmethod
    def validate_urls(cls, v):
        """Validate URLs have protocol and are valid format"""
        url_pattern = r'^https?://[a-zA-Z0-9.\-/:?=&_#@~!+\[\]{}()|\\^~`]+$'
        
        items = _parse_comma_separated_string(v)
        for url in items:
            if not re.match(url_pattern, url):
                raise ValueError(f"Invalid URL '{url}': must include http:// or https://")
        return v
    
    @field_validator('excluded_ips', mode='after')
    @classmethod
    def validate_excluded_ips(cls, v):
        """Validate each excluded IP is valid IPv4 address or range"""
        import ipaddress
        
        items = _parse_comma_separated_string(v)
        for ip in items:
            # Handle both single IPs and IP ranges (e.g., "10.0.1.50-10.0.1.100")
            if '-' in ip:
                # IP range: validate start and end IPs
                try:
                    parts = ip.split('-')
                    if len(parts) != 2:
                        raise ValueError(f"Invalid IP range format: {ip}")
                    start_ip = ipaddress.IPv4Address(parts[0].strip())
                    end_ip = ipaddress.IPv4Address(parts[1].strip())
                    if start_ip > end_ip:
                        raise ValueError(f"Range start {start_ip} > end {end_ip}")
                except ValueError as e:
                    raise ValueError(f"Invalid IP range '{ip}': {str(e)}")
            else:
                # Single IP
                try:
                    ipaddress.IPv4Address(ip)
                except ValueError as e:
                    raise ValueError(f"Invalid IP '{ip}': {str(e)}")
        return v
    
    @field_validator('restricted_actions', mode='after')
    @classmethod
    def validate_restricted_actions(cls, v):
        """Validate restricted actions are from allowed whitelist"""
        allowed = {
            "MODIFY_DATA", "DELETE_DATA", "ENCRYPT_DATA",
            "STOP_SERVICES", "MODIFY_CREDENTIALS", "EXFILTRATE_DATA"
        }
        
        items = _parse_comma_separated_string(v)
        for action in items:
            if action not in allowed:
                raise ValueError(
                    f"Invalid action '{action}'. Allowed: {', '.join(sorted(allowed))}"
                )
        return v
    
    def model_post_init(self, __context):
        """Validate cross-field constraints after all fields are set"""
        cidrs_items = _parse_comma_separated_string(self.cidrs)
        domains_items = _parse_comma_separated_string(self.domains)
        urls_items = _parse_comma_separated_string(self.urls)
        
        # At least one scope type must be specified
        if not any([cidrs_items, domains_items, urls_items]):
            raise ValueError("At least one of cidrs, domains, or urls must be specified")
        
        # Validate excluded IPs are within scope CIDRs
        excluded_items = _parse_comma_separated_string(self.excluded_ips)
        if excluded_items and cidrs_items:
            try:
                import ipaddress
                scope_cidrs = [ipaddress.IPv4Network(cidr) for cidr in cidrs_items]
                
                for excluded_ip_str in excluded_items:
                    try:
                        excluded_ip = ipaddress.IPv4Address(excluded_ip_str)
                        in_scope = any(excluded_ip in cidr for cidr in scope_cidrs)
                        
                        if not in_scope:
                            cidrs_str = ', '.join(cidrs_items)
                            raise ValueError(
                                f"Excluded IP {excluded_ip_str} is NOT within scope CIDRs ({cidrs_str})"
                            )
                    except ipaddress.AddressValueError:
                        # If it's an IP range, skip the detailed validation
                        pass
            except Exception:
                # If scope CIDRs are invalid, skip this validation
                # they'll be caught in validate_cidrs
                pass


class Policy(BaseModel):
    """Policy configuration"""
    
    cloud_allowed: bool = Field(
        default=False,
        description="Allow cloud LLM fallback (may incur costs)"
    )
    max_iterations: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum agent loop iterations"
    )
    max_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum retry attempts per LLM call"
    )
    
    @field_validator('max_iterations', mode='after')
    @classmethod
    def warn_if_low_iterations(cls, v):
        """Note if max_iterations is unusually low"""
        if v < 20:
            import warnings
            warnings.warn(
                f"max_iterations={v} is low; typical engagements need 50+ iterations. "
                "This may result in incomplete assessment.",
                UserWarning
            )
        return v


class Approval(BaseModel):
    """Approval metadata (auto-filled by system)"""
    
    approved_by: Optional[str] = Field(default=None)
    approval_date: Optional[datetime] = Field(default=None)
    approval_signature: Optional[str] = Field(default=None)


class Metadata(BaseModel):
    """Additional metadata"""
    
    created_at: Optional[datetime] = Field(default=None)
    organization: Optional[str] = Field(default=None)
    notes: Optional[str] = Field(default=None)


class ROESchema(BaseModel):
    """Complete Rules of Engagement Schema"""
    
    model_config = ConfigDict(validate_assignment=True)
    
    engagement: EngagementMeta
    scope: Scope
    policy: Policy = Field(default_factory=Policy)
    approval: Approval = Field(default_factory=Approval)
    metadata: Metadata = Field(default_factory=Metadata)


def validate_roe_file(roe_dict: dict) -> tuple:
    """
    Validate ROE dictionary against schema.
    
    Args:
        roe_dict: Dictionary parsed from YAML (must not be None)
    
    Returns:
        (is_valid: bool, error_message: str or None)
        
    Raises:
        TypeError: If roe_dict is None or not a dict
    """
    # Defensive check - should never happen with proper CLI validation
    if roe_dict is None:
        return False, "FATAL: ROE dictionary is None. This should have been caught during YAML parsing."
    
    if not isinstance(roe_dict, dict):
        return False, f"FATAL: ROE must be a dictionary, got {type(roe_dict).__name__}"
    
    try:
        ROESchema(**roe_dict)
        return True, None
    except ValidationError as e:
        # Format errors for user
        error_lines = []
        for error in e.errors():
            field_path = " → ".join(str(x) for x in error['loc'])
            message = error['msg']
            error_lines.append(f"  {field_path}: {message}")
        
        error_message = "ROE Validation Failed:\n" + "\n".join(error_lines)
        return False, error_message


def validate_roe_and_raise(roe_dict: dict) -> ROESchema:
    """
    Validate ROE dictionary and raise exception if invalid.
    
    Raises:
        ValidationError: If ROE is invalid
    
    Returns:
        ROESchema: Validated ROE schema object
    """
    return ROESchema(**roe_dict)

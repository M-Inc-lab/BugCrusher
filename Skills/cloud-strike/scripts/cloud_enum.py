#!/usr/bin/env python3
"""
BugCrusher — Cloud Strike: AWS/GCP/Azure Attack Surface Mapper
Finds misconfigurations, exposed buckets, IAM overpermissions.
"""

import boto3
import requests
import json
import re
from botocore.config import Config
from typing import Dict, List, Optional, Tuple

class CloudStrike:
    """
    AWS/GCP/Azure attack surface enumeration.
    
    Usage:
        cloud = CloudStrike(provider='aws', region='us-east-1')
        findings = cloud.scan_s3()
"""Adapter for a remote HTTP agent."""

import logging
from typing import Any
import httpx
from nti_attack.adapters.base import AgentAdapter, AgentResponse

logger = logging.getLogger(__name__)


class HttpAgentAdapter(AgentAdapter):
    def __init__(self, base_url: str, timeout: float = 30.0, headers=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = headers or {}

    def invoke(self, payload: Any) -> AgentResponse:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.post(
                    f"{self.base_url}/invoke",
                    json={"input": payload} if not isinstance(payload, dict) else payload,
                    headers=self.headers,
                )
                if r.status_code >= 400:
                    return AgentResponse(output="", error=f"HTTP {r.status_code}")
                data = r.json()
                return AgentResponse(output=str(data.get("output", "")), raw=data)
        except Exception as e:
            return AgentResponse(output="", error=str(e))

    def reset(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                client.post(f"{self.base_url}/reset", headers=self.headers)
        except httpx.HTTPError as e:
            logger.warning("Failed to reset HTTP agent at %s: %s", self.base_url, e)

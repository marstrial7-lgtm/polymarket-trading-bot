"""
Client Module - API Clients for Polymarket
"""

import time
import hmac
import hashlib
import base64
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import requests

from .config import BuilderConfig
from .http import ThreadLocalSessionMixin


class ApiError(Exception):
    pass


class AuthenticationError(ApiError):
    pass


class OrderError(ApiError):
    pass


@dataclass
class ApiCredentials:
    """User-level API credentials for CLOB."""
    api_key: str
    secret: str
    passphrase: str

    @classmethod
    def load(cls, filepath: str) -> "ApiCredentials":
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls(
            api_key=data.get("apiKey", ""),
            secret=data.get("secret", ""),
            passphrase=data.get("passphrase", ""),
        )

    def is_valid(self) -> bool:
        return bool(self.api_key and self.secret and self.passphrase)


class ApiClient(ThreadLocalSessionMixin):
    def __init__(self, base_url: str, timeout: int = 30, retry_count: int = 3):
        super().__init__()
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.retry_count = retry_count

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Any] = None,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        request_headers = {"Content-Type": "application/json"}

        if headers:
            request_headers.update(headers)

        last_error = None
        for attempt in range(self.retry_count):
            try:
                session = self.session
                if method.upper() == "GET":
                    response = session.get(url, headers=request_headers, params=params, timeout=self.timeout)
                elif method.upper() == "POST":
                    response = session.post(url, headers=request_headers, json=data, params=params, timeout=self.timeout)
                elif method.upper() == "DELETE":
                    response = session.delete(url, headers=request_headers, json=data, params=params, timeout=self.timeout)
                else:
                    raise ApiError(f"Unsupported method: {method}")

                response.raise_for_status()
                return response.json() if response.text else {}

            except requests.exceptions.RequestException as e:
                last_error = e
                if attempt < self.retry_count - 1:
                    time.sleep(2 ** attempt)

        raise ApiError(f"Request failed after {self.retry_count} attempts: {last_error}")


class ClobClient(ApiClient):
    def __init__(
        self,
        host: str = "https://clob.polymarket.com",
        chain_id: int = 137,
        signature_type: int = 2,
        funder: str = "",
        api_creds: Optional[ApiCredentials] = None,
        builder_creds: Optional[BuilderConfig] = None,
        timeout: int = 30
    ):
        super().__init__(base_url=host, timeout=timeout)
        self.host = host
        self.chain_id = chain_id
        self.signature_type = signature_type
        self.funder = funder
        self.api_creds = api_creds
        self.builder_creds = builder_creds

    def _build_headers(self, method: str, path: str, body: str = "") -> Dict[str, str]:
        headers = {}

        # Builder HMAC authentication
        if self.builder_creds and self.builder_creds.is_configured():
            timestamp = str(int(time.time()))
            message = f"{timestamp}{method}{path}{body}"
            signature = hmac.new(
                self.builder_creds.api_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            headers.update({
                "POLY_BUILDER_API_KEY": self.builder_creds.api_key,
                "POLY_BUILDER_TIMESTAMP": timestamp,
                "POLY_BUILDER_PASSPHRASE": self.builder_creds.api_passphrase,
                "POLY_BUILDER_SIGNATURE": signature,
            })

        # User API credentials (L2 authentication)
        if self.api_creds and self.api_creds.is_valid():
            timestamp = str(int(time.time()))

            message = f"{timestamp}{method}{path}"
            if body:
                message += body

            # Try standard base64 decode first, then urlsafe, then raw
            secret = self.api_creds.secret
            decoded_secret = None
            for decode_fn in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    # Add padding if needed
                    padded = secret + "=" * (4 - len(secret) % 4)
                    decoded_secret = decode_fn(padded)
                    break
                except Exception:
                    continue

            if decoded_secret:
                h = hmac.new(decoded_secret, message.encode("utf-8"), hashlib.sha256)
                signature = base64.b64encode(h.digest()).decode("utf-8")
            else:
                # Fallback: use secret directly
                h = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256)
                signature = base64.b64encode(h.digest()).decode("utf-8")

            headers.update({
                "POLY_ADDRESS": self.funder,
                "POLY_API_KEY": self.api_creds.api_key,
                "POLY_TIMESTAMP": timestamp,
                "POLY_PASSPHRASE": self.api_creds.passphrase,
                "POLY_SIGNATURE": signature,
            })

        return headers

    def derive_api_key(self, signer: "OrderSigner", nonce: int = 0) -> ApiCredentials:
        timestamp = str(int(time.time()))
        auth_signature = signer.sign_auth_message(timestamp=timestamp, nonce=nonce)
        headers = {
            "POLY_ADDRESS": signer.address,
            "POLY_SIGNATURE": auth_signature,
            "POLY_TIMESTAMP": timestamp,
            "POLY_NONCE": str(nonce),
        }
        response = self._request("GET", "/auth/derive-api-key", headers=headers)
        return ApiCredentials(
            api_key=response.get("apiKey", ""),
            secret=response.get("secret", ""),
            passphrase=response.get("passphrase", ""),
        )

    def create_api_key(self, signer: "OrderSigner", nonce: int = 0) -> ApiCredentials:
        timestamp = str(int(time.time()))
        auth_signature = signer.sign_auth_message(timestamp=timestamp, nonce=nonce)
        headers = {
            "POLY_ADDRESS": signer.address,
            "POLY_SIGNATURE": auth_signature,
            "POLY_TIMESTAMP": timestamp,
            "POLY_NONCE": str(nonce),
        }
        response = self._request("POST", "/auth/api-key", headers=headers)
        return ApiCredentials(
            api_key=response.get("apiKey", ""),
            secret=response.get("secret", ""),
            passphrase=response.get("passphrase", ""),
        )

    def create_or_derive_api_key(self, signer: "OrderSigner", nonce: int = 0) -> ApiCredentials:
        try:
            return self.create_api_key(signer, nonce)
        except Exception:
            return self.derive_api_key(signer, nonce)

    def set_api_creds(self, creds: ApiCredentials) -> None:
        self.api_creds = creds

    def get_order_book(self, token_id: str) -> Dict[str, Any]:
        return self._request("GET", "/book", params={"token_id": token_id})

    def get_market_price(self, token_id: str) -> Dict[str, Any]:
        return self._request("GET", "/price", params={"token_id": token_id})

    def get_open_orders(self) -> List[Dict[str, Any]]:
        endpoint = "/data/orders"
        headers = self._build_headers("GET", endpoint)
        result = self._request("GET", endpoint, headers=headers)
        if isinstance(result, dict) and "data" in result:
            return result.get("data", [])
        return result if isinstance(result, list) else []

    def get_order(self, order_id: str) -> Dict[str, Any]:
        endpoint = f"/data/order/{order_id}"
        headers = self._build_headers("GET", endpoint)
        return self._request("GET", endpoint, headers=headers)

    def get_trades(self, token_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        endpoint = "/data/trades"
        headers = self._build_headers("GET", endpoint)
        params: Dict[str, Any] = {"limit": limit}
        if token_id:
            params["token_id"] = token_id
        result = self._request("GET", endpoint, headers=headers, params=params)
        if isinstance(result, dict) and "data" in result:
            return result.get("data", [])
        return result if isinstance(result, list) else []

    def post_order(self, signed_order: Dict[str, Any], order_type: str = "GTC") -> Dict[str, Any]:
        endpoint = "/order"
        body = {
            "order": signed_order.get("order", signed_order),
            "owner": self.funder,
            "orderType": order_type,
        }
        if "signature" in signed_order:
            body["signature"] = signed_order["signature"]
        body_json = json.dumps(body, separators=(',', ':'))
        headers = self._build_headers("POST", endpoint, body_json)
        return self._request("POST", endpoint, data=body, headers=headers)

    def cancel_order(self, order_id: str) -> Dict[str, Any]:
        endpoint = "/order"
        body = {"orderID": order_id}
        body_json = json.dumps(body, separators=(',', ':'))
        headers = self._build_headers("DELETE", endpoint, body_json)
        return self._request("DELETE", endpoint, data=body, headers=headers)

    def cancel_orders(self, order_ids: List[str]) -> Dict[str, Any]:
        endpoint = "/orders"
        body_json = json.dumps(order_ids, separators=(',', ':'))
        headers = self._build_headers("DELETE", endpoint, body_json)
        return self._request("DELETE", endpoint, data=order_ids, headers=headers)

    def cancel_all_orders(self) -> Dict[str, Any]:
        endpoint = "/cancel-all"
        headers = self._build_headers("DELETE", endpoint)
        return self._request("DELETE", endpoint, headers=headers)

    def cancel_market_orders(self, market: Optional[str] = None, asset_id: Optional[str] = None) -> Dict[str, Any]:
        endpoint = "/cancel-market-orders"
        body = {}
        if market:
            body["market"] = market
        if asset_id:
            body["asset_id"] = asset_id
        body_json = json.dumps(body, separators=(',', ':')) if body else ""
        headers = self._build_headers("DELETE", endpoint, body_json)
        return self._request("DELETE", endpoint, data=body if body else None, headers=headers)


class RelayerClient(ApiClient):
    def __init__(
        self,
        host: str = "https://relayer-v2.polymarket.com",
        chain_id: int = 137,
        builder_creds: Optional[BuilderConfig] = None,
        tx_type: str = "SAFE",
        timeout: int = 60
    ):
        super().__init__(base_url=host, timeout=timeout)
        self.chain_id = chain_id
        self.builder_creds = builder_creds
        self.tx_type = tx_type

    def _build_headers(self, method: str, path: str, body: str = "") -> Dict[str, str]:
        if not self.builder_creds or not self.builder_creds.is_configured():
            raise AuthenticationError("Builder credentials required for relayer")
        timestamp = str(int(time.time()))
        message = f"{timestamp}{method}{path}{body}"
        signature = hmac.new(
            self.builder_creds.api_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return {
            "POLY_BUILDER_API_KEY": self.builder_creds.api_key,
            "POLY_BUILDER_TIMESTAMP": timestamp,
            "POLY_BUILDER_PASSPHRASE": self.builder_creds.api_passphrase,
            "POLY_BUILDER_SIGNATURE": signature,
        }

    def deploy_safe(self, safe_address: str) -> Dict[str, Any]:
        endpoint = "/deploy"
        body = {"safeAddress": safe_address}
        body_json = json.dumps(body, separators=(',', ':'))
        headers = self._build_headers("POST", endpoint, body_json)
        return self._request("POST", endpoint, data=body, headers=headers)

    def approve_usdc(self, safe_address: str, spender: str, amount: int) -> Dict[str, Any]:
        endpoint = "/approve-usdc"
        body = {"safeAddress": safe_address, "spender": spender, "amount": str(amount)}
        body_json = json.dumps(body, separators=(',', ':'))
        headers = self._build_headers("POST", endpoint, body_json)
        return self._request("POST", endpoint, data=body, headers=headers)

    def approve_token(self, safe_address: str, token_id: str, spender: str, amount: int) -> Dict[str, Any]:
        endpoint = "/approve-token"
        body = {"safeAddress": safe_address, "tokenId": token_id, "spender": spender, "amount": str(amount)}
        body_json = json.dumps(body, separators=(',', ':'))
        headers = self._build_headers("POST", endpoint, body_json)
        return self._request("POST", endpoint, data=body, headers=headers)

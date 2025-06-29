import base64
import json
import re
import time
import uuid
import sys
from typing import Any, Dict, Optional, Tuple

import nacl.utils
from nacl.public import PublicKey, SealedBox
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class FacebookPasswordHasher:
    PUBLIC_KEY_LENGTH = 64
    SEALED_OVERHEAD = 48
    AES_KEY_LENGTH = 32
    AES_TAG_LENGTH = 16

    def __init__(self):
        self.version = 5
        self.iv = bytes(12)

    def _seal_key(self, key: bytes, public_key_hex: str) -> bytes:
        public_key_bytes = bytes.fromhex(public_key_hex)
        box = SealedBox(PublicKey(public_key_bytes))
        return box.encrypt(key)

    def _construct_payload(self, key_id: int, public_key: str, password: str, timestamp: str) -> bytes:
        key = nacl.utils.random(self.AES_KEY_LENGTH)
        aad = timestamp.encode()
        plaintext = password.encode()
        aes = AESGCM(key)
        encrypted = aes.encrypt(self.iv, plaintext, aad)
        tag = encrypted[-self.AES_TAG_LENGTH:]
        ciphertext = encrypted[:-self.AES_TAG_LENGTH]
        sealed_key = self._seal_key(key, public_key)

        if len(sealed_key) != self.AES_KEY_LENGTH + self.SEALED_OVERHEAD:
            raise ValueError("Encrypted key length mismatch.")

        header_len = 1 + 1 + 2 + len(sealed_key) + self.AES_TAG_LENGTH
        payload = bytearray(header_len + len(ciphertext))

        i = 0
        payload[i] = 1
        i += 1
        payload[i] = key_id
        i += 1
        payload[i] = len(sealed_key) & 0xFF
        payload[i + 1] = (len(sealed_key) >> 8) & 0xFF
        i += 2
        payload[i:i + len(sealed_key)] = sealed_key
        i += len(sealed_key)
        payload[i:i + self.AES_TAG_LENGTH] = tag
        i += self.AES_TAG_LENGTH
        payload[i:] = ciphertext

        return bytes(payload)

    def _get_public_key(self) -> Dict[str, Any]:
        headers = {'user-agent': 'Mozilla/5.0'}
        try:
            response = requests.get('https://www.facebook.com/', headers=headers, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching public key from Facebook: {e}")
            raise RuntimeError("Failed to retrieve public key from Facebook.") from e

        pub_key_match = re.search(r'"publicKey"\s*:\s*"([a-zA-Z0-9+/=]+)"', response.text)
        key_id_match = re.search(r'"keyId"\s*:\s*(\d+)', response.text)

        if pub_key_match and key_id_match:
            return {
                'publicKey': pub_key_match.group(1),
                'keyId': int(key_id_match.group(1))
            }
        else:
            raise RuntimeError("Could not find public key or keyId in Facebook response. The page structure may have changed.")

    def hash(self, password: str) -> str:
        timestamp = str(int(time.time()))
        try:
            pub_data = self._get_public_key()
        except RuntimeError as e:
            print(f"Hashing failed: {e}")
            raise

        payload = self._construct_payload(pub_data['keyId'], pub_data['publicKey'], password, timestamp)
        encoded = base64.b64encode(payload).decode()
        return f"#PWD_BROWSER:{self.version}:{timestamp}:{encoded}"


class FacebookLogin:
    def __init__(self):
        self.username: Optional[str] = None
        self.password_hashed: Optional[str] = None
        self.session = requests.Session()
        self.two_fa_context: Optional[str] = None

        self.BASE_URL = "https://b-graph.facebook.com/graphql"
        self.DEVICE_ID = "897f1049-4161-56c5-81f2-3e180d0943dc"
        self.WATERFALL_ID = "f0eb4c7e-2dff-4fb3-8126-7fe27624bb02"
        self.MACHINE_ID = "sd83aCE9TA19IdDgfW-9tPJ-"
        self.SCREEN_ID = "v47cvk:5"

        self.HEADERS = {
            "X-Fb-Connection-Type": "WIFI",
            "X-Fb-Http-Engine": "Tigon/Liger",
            "X-Fb-Client-Ip": "True",
            "X-Fb-Server-Cluster": "True",
            "X-Tigon-Is-Retry": "False",
            "User-Agent": "[FBAN/FB4A;FBAV/498.1.0.64.74;FBBV/693542291;FBDM/{density=3.0,width=1080,height=1920};FBLC/en_US;FBRV/0;FBCR/S-Phone;FBMF/Samsung;FBBD/Samsung;FBPN/com.facebook.katana;FBDV/SM-T320X;FBSV/9;FBOP/1;FBCA/x86_64:arm64-v8a;]",
            "X-Fb-Device-Group": "5427",
            "X-Graphql-Request-Purpose": "fetch",
            "X-Graphql-Client-Library": "graphservice",
            "X-Fb-Net-Hni": "45201",
            "X-Fb-Sim-Hni": "45201",
            "Authorization": "OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32",
            "Accept": "application/json, text/json, text/x-json, text/javascript, application/xml, text/xml",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Host": "b-graph.facebook.com",
            "Expect": "100-continue",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip, deflate",
            "X-Fb-Privacy-Context": "3643298472347298",
            "X-Fb-Request-Analytics-Tags": '{"network_tags":{"product":"350685531728","purpose":"fetch","request_category":"graphql","retry_attempt":"0"},"application_tags":"graphservice"}'
        }

    def extract_two_fa_context(self, response_json: Dict[str, Any]) -> Optional[str]:
        try:
            bundle = response_json.get("data", {}).get("fb_bloks_action", {}).get("root_action", {}).get("action", {}).get("action_bundle", {}).get("bloks_bundle_action", "")
            if not bundle:
                return None

            for _ in range(3):
                bundle = bundle.replace('\\"', '"').replace('\\\\', '\\')
            bundle = bundle.replace('\\', '')

            patterns = [
                r'"two_step_verification_context",\s*"([^"]+)"',
                r'"(ARG[A-Za-z0-9_\-+/=]{400,})"',
                r'two_step_verification_context.*?"([A-Za-z0-9_\-+/=]{400,})"'
            ]

            for pattern in patterns:
                matches = re.findall(pattern, bundle, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    if len(match) > 400 and (match.startswith('ARG') or len(match) > 600):
                        print(f"✓ Found 2FA context: {match[:50]}...")
                        return match
            return None
        except Exception as e:
            print(f"Error extracting 2FA context: {e}")
            return None

    def extract_token_and_session(self, response_text: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        try:
            response_json = json.loads(response_text)
            bundle = response_json.get("data", {}).get("fb_bloks_action", {}).get("root_action", {}).get("action", {}).get("action_bundle", {}).get("bloks_bundle_action", "")

            if not bundle:
                return None, None

            for _ in range(3):
                bundle = bundle.replace('\\"', '"').replace('\\\\', '\\')
            bundle = bundle.replace('\\', '')

            token_match = re.search(r'"access_token":\s*"([^"]+)"', bundle)
            if not token_match:
                return None, None

            access_token = token_match.group(1)
            print(f"✓ Found access token: {access_token[:50]}...")

            start_pos = bundle.rfind('{', 0, token_match.start())
            if start_pos != -1:
                brace_count, end_pos = 1, start_pos + 1
                while end_pos < len(bundle) and brace_count > 0:
                    if bundle[end_pos] == '{':
                        brace_count += 1
                    elif bundle[end_pos] == '}':
                        brace_count -= 1
                    end_pos += 1

                if brace_count == 0:
                    try:
                        session_data = json.loads(bundle[start_pos:end_pos])
                        return access_token, session_data
                    except json.JSONDecodeError:
                        pass
            return access_token, {"access_token": access_token}
        except Exception as e:
            print(f"Error extracting token or session: {e}")
            return None, None

    def _verify_2fa(self, two_fa_code_6_digit: str) -> Tuple[Optional[str], Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
        if not self.two_fa_context:
            print("Error: Cannot verify 2FA. 2FA context is missing. Initial login step likely failed.")
            return None, None, None

        entrypoint_payload = {
            "method": "post", "pretty": "false", "format": "json", "server_timestamps": "true",
            "locale": "en_US", "purpose": "fetch",
            "fb_api_req_friendly_name": "FbBloksAppRootQuery-com.bloks.www.two_step_verification.entrypoint",
            "fb_api_caller_class": "graphservice", "client_doc_id": "105373461558397492702779496",
            "variables": json.dumps({
                "params": {
                    "params": json.dumps({
                        "client_input_params": {"device_id": self.DEVICE_ID, "is_whatsapp_installed": 0, "machine_id": self.MACHINE_ID},
                        "server_params": {
                            "family_device_id": self.DEVICE_ID, "device_id": self.DEVICE_ID,
                            "two_step_verification_context": self.two_fa_context,
                            "INTERNAL_INFRA_THEME": "harm_f,default,harm_f",
                            "flow_source": "two_factor_login", "INTERNAL_INFRA_screen_id": self.SCREEN_ID
                        }
                    }),
                    "bloks_versioning_id": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c",
                    "is_on_load_actions_supported": True, "app_id": "com.bloks.www.two_step_verification.entrypoint"
                },
                "scale": "3",
                "nt_context": {
                    "using_white_navbar": True, "styles_id": "55d2af294359fa6bbdb8e045ff01fc5e",
                    "pixel_ratio": 3, "is_push_on": True, "debug_tooling_metadata_token": None,
                    "is_flipper_enabled": False, "theme_params": [],
                    "bloks_version": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c"
                }
            }),
            "fb_api_analytics_tags": ["surfaces.fb.GraphServiceEmitter", "GraphServices"],
            "client_trace_id": str(uuid.uuid4())
        }

        try:
            print("Accessing 2FA entrypoint...")
            response = self.session.post(self.BASE_URL, headers=self.HEADERS, data=entrypoint_payload, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error in 2FA entrypoint request: {e}")
            return None, None, None

        verify_payload = {
            "generate_session_cookies": "1", "method": "post", "pretty": "false", "format": "json",
            "server_timestamps": "true", "locale": "en_US", "purpose": "fetch",
            "fb_api_req_friendly_name": "FbBloksActionRootQuery-com.bloks.www.two_step_verification.verify_code.async",
            "fb_api_caller_class": "graphservice", "client_doc_id": "119940804214876861379510865434",
            "variables": json.dumps({
                "params": {
                    "params": json.dumps({
                        "client_input_params": {
                            "auth_secure_device_id": "", "machine_id": self.MACHINE_ID, "code": two_fa_code_6_digit,
                            "should_trust_device": 1, "family_device_id": self.DEVICE_ID, "device_id": self.DEVICE_ID
                        },
                        "server_params": {
                            "INTERNAL__latency_qpl_marker_id": 36707139, "device_id": self.DEVICE_ID,
                            "challenge": "totp", "machine_id": self.MACHINE_ID,
                            "INTERNAL__latency_qpl_instance_id": 1.71160241100066E14,
                            "two_step_verification_context": self.two_fa_context, "flow_source": "two_factor_login"
                        }
                    }),
                    "bloks_versioning_id": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c",
                    "app_id": "com.bloks.www.two_step_verification.verify_code.async"
                },
                "scale": "3",
                "nt_context": {
                    "using_white_navbar": True, "styles_id": "55d2af294359fa6bbdb8e045ff01fc5e",
                    "pixel_ratio": 3, "is_push_on": True, "debug_tooling_metadata_token": None,
                    "is_flipper_enabled": False, "theme_params": [],
                    "bloks_version": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c"
                }
            }),
            "fb_api_analytics_tags": ["GraphServices"], "client_trace_id": str(uuid.uuid4())
        }

        try:
            print("Verifying 2FA code...")
            response = self.session.post(self.BASE_URL, headers=self.HEADERS, data=verify_payload, timeout=10)
            response.raise_for_status()
            verify_result = response.text
        except requests.exceptions.RequestException as e:
            print(f"Error during 2FA code verification: {e}")
            return None, None, None

        access_token, session_data = self.extract_token_and_session(verify_result)
        cookies = {name: value for name, value in self.session.cookies.items()}

        return access_token, cookies, session_data

    def login(self, username: str, password_hashed: str, two_fa_code: Optional[str] = None) -> Tuple[Optional[str], Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
        self.username = username
        self.password_hashed = password_hashed

        login_payload = {
            "method": "post", "pretty": "false", "format": "json", "server_timestamps": "true",
            "locale": "en_US", "purpose": "fetch",
            "fb_api_req_friendly_name": "FbBloksActionRootQuery-com.bloks.www.bloks.caa.login.async.send_login_request",
            "fb_api_caller_class": "graphservice", "client_doc_id": "119940804214876861379510865434",
            "variables": json.dumps({
                "params": {
                    "params": json.dumps({
                        "client_input_params": {
                            "sim_phones": [], "secure_family_device_id": "28d525de-adf8-4038-8738-13c5ab0bbb8f",
                            "attestation_result": {
                                "data": f'{{"challenge_nonce":"LCIZj+qy+ODOIc70R63qHKBm63c9u2KviVkpYFxBAkM=","username":"{self.username}"}}',
                                "signature": "MEQCIDHrmQ86yvC7yeVBi0eYpIr2cnhtaSWxYm8I+ZcZ081fAiBLzhHez6CMvaQqaFrCvfCMYker7WNLiQ4L99JpVR9K+Q==",
                                "keyHash": "32147729345a54a3c7d0ae50809aafe658b61ce31dd3ad71f09782bbb04d86e2"
                            },
                            "password": self.password_hashed, "device_id": self.DEVICE_ID, "family_device_id": self.DEVICE_ID,
                            "contact_point": self.username, "machine_id": "", "login_attempt_count": 1,
                            "event_flow": "login_manual", "auth_secure_device_id": "", "has_whatsapp_installed": 0,
                            "sso_token_map_json_string": "", "password_contains_non_ascii": "false",
                            "sim_serials": [], "client_known_key_hash": "", "encrypted_msisdn": "",
                            "should_show_nested_nta_from_aymh": 0, "accounts_list": [], "fb_ig_device_id": [],
                            "device_emails": [], "try_num": 1, "event_step": "home_page",
                            "headers_infra_flow_id": "b77007b2-c88d-4012-8aed-3c4069e32b27", "openid_tokens": {},
                            "flash_call_permission_status": {"READ_PHONE_STATE": "DENIED", "READ_CALL_LOG": "DENIED", "ANSWER_PHONE_CALLS": "DENIED"},
                            "lois_settings": {"lois_token": "", "lara_override": ""}
                        },
                        "server_params": {
                            "waterfall_id": self.WATERFALL_ID, "device_id": self.DEVICE_ID, "family_device_id": self.DEVICE_ID,
                            "login_source": "Login", "server_login_source": "login", "credential_type": "password",
                            "access_flow_version": "F2_FLOW", "INTERNAL_INFRA_THEME": "harm_f", "caller": "gslr",
                            "should_trigger_override_login_2fa_action": 0, "is_from_logged_out": 0,
                            "should_trigger_override_login_success_action": 0, "login_credential_type": "none",
                            "is_platform_login": 0, "pw_encryption_try_count": 1, "INTERNAL__latency_qpl_marker_id": 36707139,
                            "offline_experiment_group": "caa_iteration_v6_perf_fb_2", "is_from_landing_page": 0,
                            "password_text_input_id": "nmi7ws:95", "is_from_empty_password": 0,
                            "ar_event_source": "login_home_page", "username_text_input_id": "nmi7ws:94",
                            "layered_homepage_experiment_group": None, "INTERNAL__latency_qpl_instance_id": 1.42852366000951E14,
                            "reg_flow_source": "login_home_native_integration_point", "is_caa_perf_enabled": 1,
                            "is_from_password_entry_page": 0, "is_from_assistive_id": 0, "is_from_logged_in_switcher": 0
                        }
                    }),
                    "bloks_versioning_id": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c",
                    "app_id": "com.bloks.www.bloks.caa.login.async.send_login_request"
                },
                "scale": "2",
                "nt_context": {
                    "using_white_navbar": True, "styles_id": "55d2af294359fa6bbdb8e045ff01fc5e",
                    "pixel_ratio": 2, "is_push_on": True, "debug_tooling_metadata_token": None,
                    "is_flipper_enabled": False, "theme_params": [],
                    "bloks_version": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c"
                }
            }),
            "fb_api_analytics_tags": ["GraphServices"], "client_trace_id": str(uuid.uuid4())
        }

        try:
            print("Sending initial login request...")
            response = self.session.post(self.BASE_URL, headers=self.HEADERS, data=login_payload, timeout=10)
            response.raise_for_status()
            login_result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error in initial login request: {e}")
            return None, None, None
        except Exception as e:
            print(f"Unexpected error in initial login request: {e}")
            return None, None, None

        self.two_fa_context = self.extract_two_fa_context(login_result)

        if self.two_fa_context:
            # 2FA is required
            if two_fa_code:
                # User provided 2FA code, proceed to verify
                print("2FA required and code provided. Verifying...")
                return self._verify_2fa(two_fa_code)
            else:
                # 2FA required, but no code provided. Indicate to frontend to ask for code.
                print("2FA required, but no code provided. Returning 'step2' for frontend.")
                return None, None, {'next_stage': 'step2'} # Signal frontend to switch to 2FA input
        else:
            # No 2FA context obtained. Attempt to extract token from initial response.
            print("No 2FA context obtained. Attempting to extract token from initial response.")
            access_token, session_data = self.extract_token_and_session(json.dumps(login_result))
            if access_token:
                cookies = {name: value for name, value in self.session.cookies.items()}
                return access_token, cookies, session_data
            else:
                print("Could not obtain access token or session data from initial response.")
                return None, None, None


def main():
    hasher = FacebookPasswordHasher()

    try:
        input_line = sys.stdin.readline()
        if not input_line:
            raise ValueError("No input received from stdin.")

        data = json.loads(input_line.strip())

        username = data.get('username')
        password = data.get('password')
        two_fa_code_from_input = data.get('two_fa')
        login_stage = data.get('loginStage') # This will come from the frontend's payload

        if not username:
            raise ValueError("Username is missing in input.")
        print(f"Python: Received username: {username[:5]}...")

        if not password:
            raise ValueError("Password is missing in input.")
        print("Python: Received password (hidden).")

        hashed_password = hasher.hash(password)
        print(f"Python: Password hashed: {hashed_password[:20]}...")

    except json.JSONDecodeError:
        error_result = {"success": False, "details": "Invalid JSON received from stdin."}
        print(json.dumps(error_result))
        sys.exit(1)
    except ValueError as e:
        error_result = {"success": False, "details": f"Input error: {e}"}
        print(json.dumps(error_result))
        sys.exit(1)
    except RuntimeError as e: # Catch errors from hashing/public key retrieval
        error_result = {"success": False, "details": f"Hashing/Key retrieval error: {e}"}
        print(json.dumps(error_result))
        sys.exit(1)
    except Exception as e:
        error_result = {"success": False, "details": f"Unexpected error reading input: {e}"}
        print(json.dumps(error_result))
        sys.exit(1)

    fb_login = FacebookLogin()

    print("Python: --- Starting login process ---")

    actual_two_fa_code_to_send = None
    # Corrected line: Using == for string comparison in Python
    if login_stage == 'code_submitted':
        if not two_fa_code_from_input:
            error_result = {"success": False, "details": "2FA code is required for stage 'code_submitted' but was not provided."}
            print(json.dumps(error_result))
            sys.exit(1)
        actual_two_fa_code_to_send = two_fa_code_from_input
        print("Python: Proceeding to login with provided 2FA code.")
    else:
        print("Python: Initial login attempt (password only).")

    access_token, cookies, session_data = fb_login.login(
        username=username,
        password_hashed=hashed_password,
        two_fa_code=actual_two_fa_code_to_send
    )

    print("Python: --- Login process finished ---")
    if access_token:
        result = {
            "success": True,
            "next_stage": "login_success", # Indicate successful completion
            "access_token": access_token,
            "cookies": cookies,
            "session_data": session_data
        }
        print(json.dumps(result))
        sys.exit(0)
    else:
        # If login failed, determine the next step for the frontend
        if fb_login.two_fa_context and not actual_two_fa_code_to_send:
            # Password was correct, 2FA context was found, but no code was provided by frontend.
            # Tell frontend to ask for the 2FA code.
            final_result = {
                "success": False,
                "next_stage": "step2", # Signal frontend to go to 2FA input stage
                "error_message": "Authentication required. Please enter the code sent to your device."
            }
        else:
            # General login failure (wrong password, invalid credentials, etc.)
            final_result = {
                "success": False,
                "next_stage": "step1", # Return to password input or a generic error
                "error_message": "Login failed. Please check your credentials or try again."
            }
        
        print(json.dumps(final_result))
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
MQTT Proxy
Captures and parses MQTT protocol traffic (versions 3.1, 3.1.1, 5.0).
"""

import struct
import socket
from typing import Tuple, Optional

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger, ProtocolInfo


# MQTT Control Packet Types
MQTT_PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",  # MQTT 5.0 only
}

# MQTT QoS Levels
MQTT_QOS = {
    0: "At most once",
    1: "At least once",
    2: "Exactly once",
}

# MQTT Connect Return Codes (3.1.1)
MQTT_CONNACK_CODES = {
    0: "Connection Accepted",
    1: "Unacceptable Protocol Version",
    2: "Identifier Rejected",
    3: "Server Unavailable",
    4: "Bad Username or Password",
    5: "Not Authorized",
}


class MQTTProxy(BaseProxy):
    """
    MQTT protocol-aware proxy.
    
    Features:
    - Full MQTT packet parsing
    - Topic extraction from PUBLISH/SUBSCRIBE
    - Client ID extraction from CONNECT
    - QoS level identification
    - Will message detection
    - Username/password detection (not logged for security)
    
    Frame Structure:
    +------------------+------------------+------------------+
    | Fixed Header     | Variable Length  | Payload          |
    | (1+ bytes)       | (1-4 bytes)      | (variable)       |
    +------------------+------------------+------------------+
    
    Example:
        config = ProxyConfig(
            listen_port=1883,
            backend_host="127.0.0.1",
            backend_port=11883,
            protocol="mqtt",
            node_id="node-01",
            deployment_id="broker-01",
        )
        logger = UnifiedLogger("/var/log/honeypot", "node-01", "broker-01")
        proxy = MQTTProxy(config, logger)
        proxy.start()
    """
    
    def __init__(self, config: ProxyConfig, logger: UnifiedLogger):
        super().__init__(config, logger)
        self._client_info: dict = {}  # Store client info per session
    
    def parse_request(self, data: bytes, session_id: str = "") -> dict:
        """Parse MQTT packet from client"""
        return self._parse_mqtt_packet(data, session_id, is_request=True)
    
    def parse_response(self, data: bytes, request_context: dict = None) -> dict:
        """Parse MQTT packet from broker"""
        return self._parse_mqtt_packet(data, "", is_request=False)
    
    def _parse_mqtt_packet(self, data: bytes, session_id: str, is_request: bool) -> dict:
        """Parse MQTT packet"""
        result = {
            "valid": False,
            "raw_length": len(data),
        }
        
        if len(data) < 2:
            result["error"] = "Packet too short"
            return result
        
        try:
            # Parse fixed header
            byte1 = data[0]
            packet_type = (byte1 >> 4) & 0x0F
            flags = byte1 & 0x0F
            
            result["mqtt.packet_type"] = packet_type
            result["mqtt.packet_type_name"] = MQTT_PACKET_TYPES.get(packet_type, f"Unknown ({packet_type})")
            result["mqtt.flags"] = flags
            
            # Parse remaining length (variable-length encoding)
            remaining_length, header_size = self._decode_remaining_length(data[1:])
            result["mqtt.remaining_length"] = remaining_length
            
            # Get variable header and payload
            payload_start = 1 + header_size
            payload = data[payload_start:payload_start + remaining_length]
            
            # Parse packet-specific data
            if packet_type == 1:  # CONNECT
                self._parse_connect(payload, result, session_id)
            elif packet_type == 2:  # CONNACK
                self._parse_connack(payload, result)
            elif packet_type == 3:  # PUBLISH
                self._parse_publish(payload, flags, result)
            elif packet_type == 8:  # SUBSCRIBE
                self._parse_subscribe(payload, result)
            elif packet_type == 9:  # SUBACK
                self._parse_suback(payload, result)
            elif packet_type == 10:  # UNSUBSCRIBE
                self._parse_unsubscribe(payload, result)
            elif packet_type == 12:  # PINGREQ
                result["mqtt.ping"] = True
            elif packet_type == 13:  # PINGRESP
                result["mqtt.pong"] = True
            elif packet_type == 14:  # DISCONNECT
                result["mqtt.disconnect"] = True
            
            result["valid"] = True
            
        except Exception as e:
            result["error"] = f"Parse error: {e}"
        
        return result
    
    def _decode_remaining_length(self, data: bytes) -> Tuple[int, int]:
        """Decode MQTT variable-length remaining length field"""
        multiplier = 1
        value = 0
        index = 0
        
        while index < len(data) and index < 4:
            byte = data[index]
            value += (byte & 0x7F) * multiplier
            multiplier *= 128
            index += 1
            
            if (byte & 0x80) == 0:
                break
        
        return value, index
    
    def _decode_string(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Decode MQTT UTF-8 string (length-prefixed)"""
        if offset + 2 > len(data):
            return "", offset
        
        length = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        
        if offset + length > len(data):
            return "", offset
        
        try:
            string = data[offset:offset+length].decode("utf-8", errors="replace")
        except Exception:
            string = data[offset:offset+length].hex()
        
        return string, offset + length
    
    def _parse_connect(self, payload: bytes, result: dict, session_id: str):
        """Parse CONNECT packet"""
        offset = 0
        
        # Protocol Name
        protocol_name, offset = self._decode_string(payload, offset)
        result["mqtt.protocol_name"] = protocol_name
        
        if offset >= len(payload):
            return
        
        # Protocol Level
        protocol_level = payload[offset]
        offset += 1
        result["mqtt.protocol_version"] = protocol_level
        
        if protocol_level == 4:
            result["mqtt.version_name"] = "MQTT 3.1.1"
        elif protocol_level == 5:
            result["mqtt.version_name"] = "MQTT 5.0"
        elif protocol_level == 3:
            result["mqtt.version_name"] = "MQTT 3.1"
        
        if offset >= len(payload):
            return
        
        # Connect Flags
        connect_flags = payload[offset]
        offset += 1
        
        result["mqtt.clean_session"] = bool(connect_flags & 0x02)
        result["mqtt.will_flag"] = bool(connect_flags & 0x04)
        result["mqtt.will_qos"] = (connect_flags >> 3) & 0x03
        result["mqtt.will_retain"] = bool(connect_flags & 0x20)
        result["mqtt.has_password"] = bool(connect_flags & 0x40)
        result["mqtt.has_username"] = bool(connect_flags & 0x80)
        
        if offset + 2 > len(payload):
            return
        
        # Keep Alive
        keep_alive = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2
        result["mqtt.keep_alive"] = keep_alive
        
        # MQTT 5.0 Properties (skip for now)
        if protocol_level == 5 and offset < len(payload):
            props_len, props_size = self._decode_remaining_length(payload[offset:])
            offset += props_size + props_len
        
        # Client ID
        client_id, offset = self._decode_string(payload, offset)
        result["mqtt.client_id"] = client_id
        
        # Store client info for session
        self._client_info[session_id] = {"client_id": client_id}
        
        # Will Topic/Message (if will flag set)
        if connect_flags & 0x04:
            will_topic, offset = self._decode_string(payload, offset)
            result["mqtt.will_topic"] = will_topic
            
            will_message, offset = self._decode_string(payload, offset)
            result["mqtt.will_message_length"] = len(will_message)
        
        # Username (if flag set) - indicate presence but don't log value
        if connect_flags & 0x80:
            username, offset = self._decode_string(payload, offset)
            result["mqtt.username_present"] = True
            result["mqtt.username_length"] = len(username)
        
        # Password (if flag set) - indicate presence but don't log value
        if connect_flags & 0x40:
            result["mqtt.password_present"] = True
    
    def _parse_connack(self, payload: bytes, result: dict):
        """Parse CONNACK packet"""
        if len(payload) < 2:
            return
        
        # Session Present flag
        session_present = payload[0] & 0x01
        result["mqtt.session_present"] = bool(session_present)
        
        # Return Code
        return_code = payload[1]
        result["mqtt.return_code"] = return_code
        result["mqtt.return_code_name"] = MQTT_CONNACK_CODES.get(return_code, f"Unknown ({return_code})")
        result["mqtt.connection_accepted"] = return_code == 0
    
    def _parse_publish(self, payload: bytes, flags: int, result: dict):
        """Parse PUBLISH packet"""
        offset = 0
        
        # QoS and flags from fixed header
        dup = bool(flags & 0x08)
        qos = (flags >> 1) & 0x03
        retain = bool(flags & 0x01)
        
        result["mqtt.dup"] = dup
        result["mqtt.qos"] = qos
        result["mqtt.qos_name"] = MQTT_QOS.get(qos, f"Unknown ({qos})")
        result["mqtt.retain"] = retain
        
        # Topic Name
        topic, offset = self._decode_string(payload, offset)
        result["mqtt.topic"] = topic
        
        # Packet Identifier (only for QoS > 0)
        if qos > 0 and offset + 2 <= len(payload):
            packet_id = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2
            result["mqtt.packet_id"] = packet_id
        
        # Message payload
        message_payload = payload[offset:]
        result["mqtt.payload_length"] = len(message_payload)
        
        # Try to decode as UTF-8
        try:
            message = message_payload.decode("utf-8", errors="replace")
            if len(message) <= 500:  # Only log short messages
                result["mqtt.payload"] = message
            else:
                result["mqtt.payload_preview"] = message[:200]
        except Exception:
            result["mqtt.payload_hex"] = message_payload[:100].hex()
    
    def _parse_subscribe(self, payload: bytes, result: dict):
        """Parse SUBSCRIBE packet"""
        offset = 0
        
        # Packet Identifier
        if len(payload) >= 2:
            packet_id = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2
            result["mqtt.packet_id"] = packet_id
        
        # Topic Filters
        topics = []
        while offset < len(payload):
            topic, offset = self._decode_string(payload, offset)
            if not topic:
                break
            
            qos = payload[offset] if offset < len(payload) else 0
            offset += 1
            
            topics.append({
                "topic": topic,
                "qos": qos,
            })
        
        result["mqtt.topics"] = topics
        result["mqtt.topic_count"] = len(topics)
    
    def _parse_suback(self, payload: bytes, result: dict):
        """Parse SUBACK packet"""
        offset = 0
        
        # Packet Identifier
        if len(payload) >= 2:
            packet_id = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2
            result["mqtt.packet_id"] = packet_id
        
        # Return Codes
        return_codes = list(payload[offset:])
        result["mqtt.return_codes"] = return_codes
        result["mqtt.all_accepted"] = all(rc < 128 for rc in return_codes)
    
    def _parse_unsubscribe(self, payload: bytes, result: dict):
        """Parse UNSUBSCRIBE packet"""
        offset = 0
        
        # Packet Identifier
        if len(payload) >= 2:
            packet_id = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2
            result["mqtt.packet_id"] = packet_id
        
        # Topic Filters
        topics = []
        while offset < len(payload):
            topic, offset = self._decode_string(payload, offset)
            if not topic:
                break
            topics.append(topic)
        
        result["mqtt.topics"] = topics
    
    def get_protocol_info(self) -> ProtocolInfo:
        """Return MQTT protocol info"""
        return ProtocolInfo(
            name="mqtt",
            layer="application",
            version="3.1.1",
        )
    
    def _read_response(self, backend_sock: socket.socket, request_context: dict) -> bytes:
        """
        Read complete MQTT packet.
        MQTT uses variable-length encoding for remaining length.
        
        Fixed header structure:
        - Byte 0: Packet type (4 bits) + Flags (4 bits)
        - Byte 1+: Remaining length (variable, 1-4 bytes)
        """
        # Read first byte (packet type + flags)
        first_byte = backend_sock.recv(1)
        if not first_byte:
            return b""
        
        # Read remaining length (variable length encoding)
        remaining_length_bytes = b""
        remaining_length = 0
        multiplier = 1
        
        while True:
            byte = backend_sock.recv(1)
            if not byte:
                # Return what we have so far
                return first_byte + remaining_length_bytes
            
            remaining_length_bytes += byte
            remaining_length += (byte[0] & 0x7F) * multiplier
            multiplier *= 128
            
            # Check if this is the last byte of remaining length
            if (byte[0] & 0x80) == 0:
                break
            
            # Remaining length is at most 4 bytes
            if len(remaining_length_bytes) >= 4:
                break
        
        # Read the payload based on remaining length
        payload = b""
        while len(payload) < remaining_length:
            chunk = backend_sock.recv(min(remaining_length - len(payload), self.config.buffer_size))
            if not chunk:
                break
            payload += chunk
        
        return first_byte + remaining_length_bytes + payload
    
    def _cleanup_session(self, session_id: str):
        """Clean up session-specific client info to prevent memory leak"""
        self._client_info.pop(session_id, None)

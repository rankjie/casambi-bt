"""
Android App Compatible Parser for Casambi Switch Events

This module implements the exact parsing logic from the decompiled Android app
to compare with our current implementation.
"""

import struct
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class AndroidPacketParser:
    """Parser that follows the exact Android app implementation"""
    
    @staticmethod
    def parse_packet_header(data: bytes, pos: int = 0) -> Tuple[Dict[str, Any], int]:
        """
        Parse packet header according to Android app C1775b.Q method (lines 230-243)
        
        Returns: (header_dict, new_position)
        """
        if len(data) - pos < 9:
            raise ValueError("Insufficient data for packet header")
            
        # Read header (2 bytes)
        unsigned_short = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        
        # Extract flags from header
        has_origin_handle = (unsigned_short & 64) != 0    # bit 6
        is_unique = (unsigned_short & 128) != 0           # bit 7
        has_session = (unsigned_short & 256) != 0         # bit 8
        has_origin_handle_alt = (unsigned_short & 512) != 0  # bit 9
        flag_1024 = (unsigned_short & 1024) != 0         # bit 10
        
        # Read command type (1 byte) - this is the EnumC1777d ordinal
        command_type = data[pos] & 0xFF
        pos += 1
        
        # Read origin (2 bytes)
        origin = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        
        # Read target (2 bytes)
        target = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        
        # Extract lifetime from header bits 11-14
        lifetime = (unsigned_short >> 11) & 15
        
        # Read age (2 bytes)
        age = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        
        # Read optional origin handle if flag is set
        origin_handle = None
        if has_origin_handle_alt:
            origin_handle = data[pos] & 0xFF
            pos += 1
            
        # Extract payload length from header bits 0-5
        payload_length = unsigned_short & 63
        
        header = {
            'header_raw': unsigned_short,
            'command_type': command_type,
            'origin': origin,
            'target': target,
            'lifetime': lifetime,
            'age': age,
            'origin_handle': origin_handle,
            'payload_length': payload_length,
            'flags': {
                'has_origin_handle': has_origin_handle,
                'is_unique': is_unique,
                'has_session': has_session,
                'has_origin_handle_alt': has_origin_handle_alt,
                'flag_1024': flag_1024
            }
        }
        
        return header, pos
    
    @staticmethod
    def parse_switch_event(header: Dict[str, Any], payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse switch event according to Android app logic (lines 271-280)
        
        The Android app checks:
        - target & 0xFF == 6 (lower byte of target must be 6)
        - command_type ordinal must be between 29-36 (FunctionButtonEvent0-7)
        - payload must have at least 3 bytes
        """
        target_type = header['target'] & 0xFF
        target_unit_id = header['target'] >> 8
        command_type = header['command_type']
        
        # Check if this is a switch event
        if target_type != 6:
            return None
            
        # Check if command type is in range for button events (29-36)
        if command_type < 29 or command_type > 36:
            return None
            
        # Check payload length
        if len(payload) < 3:
            logger.warning(f"Switch event payload too short: {len(payload)} bytes")
            return None
            
        # Parse according to Android logic
        first_byte = payload[0]
        button_index = command_type - 29  # 0-7
        
        # Extract parameters from first byte
        param_p = (first_byte >> 3) & 15  # bits 3-6
        param_s = first_byte & 7          # bits 0-2
        state = 1 if (first_byte & 128) else 0  # bit 7
        
        return {
            'unit_id': target_unit_id,
            'button': button_index,
            'state': state,  # 1 = pressed, 0 = released
            'param_p': param_p,
            'param_s': param_s,
            'target_type': target_type,
            'command_type': command_type,
            'payload_hex': payload.hex(),
            'android_log': f"Unit {target_unit_id} Switch event: #{button_index} (P{param_p} S{param_s}) = {state}"
        }
    
    @staticmethod
    def parse_complete_packet(data: bytes) -> Dict[str, Any]:
        """Parse a complete packet and extract switch events if present"""
        try:
            header, payload_start = AndroidPacketParser.parse_packet_header(data)
            
            # Read payload
            payload_length = header['payload_length']
            if len(data) - payload_start < payload_length:
                raise ValueError(f"Insufficient data for payload: need {payload_length}, have {len(data) - payload_start}")
                
            payload = data[payload_start:payload_start + payload_length]
            
            # Try to parse as switch event
            switch_event = AndroidPacketParser.parse_switch_event(header, payload)
            
            return {
                'header': header,
                'payload': payload.hex(),
                'switch_event': switch_event
            }
            
        except Exception as e:
            logger.error(f"Failed to parse packet: {e}")
            return {'error': str(e), 'data': data.hex()}


# Command type constants from EnumC1777d
class FunctionType:
    """Function type constants from Android app"""
    BUTTON_EVENT_0 = 29
    BUTTON_EVENT_1 = 30
    BUTTON_EVENT_2 = 31
    BUTTON_EVENT_3 = 32
    BUTTON_EVENT_4 = 33
    BUTTON_EVENT_5 = 34
    BUTTON_EVENT_6 = 35
    BUTTON_EVENT_7 = 36


def compare_with_current_parser(data: bytes, current_parser_result: Dict[str, Any]) -> Dict[str, Any]:
    """Compare Android parser results with current implementation"""
    android_result = AndroidPacketParser.parse_complete_packet(data)
    
    comparison = {
        'android_parser': android_result,
        'current_parser': current_parser_result,
        'differences': []
    }
    
    # Compare results
    if android_result.get('switch_event') and current_parser_result:
        android_evt = android_result['switch_event']
        
        # Check unit_id
        if android_evt['unit_id'] != current_parser_result.get('unit_id'):
            comparison['differences'].append({
                'field': 'unit_id',
                'android': android_evt['unit_id'],
                'current': current_parser_result.get('unit_id')
            })
            
        # Check button
        if android_evt['button'] != current_parser_result.get('button'):
            comparison['differences'].append({
                'field': 'button',
                'android': android_evt['button'],
                'current': current_parser_result.get('button')
            })
            
        # Map Android state to current event names
        android_event = 'button_press' if android_evt['state'] == 1 else 'button_release'
        if android_event != current_parser_result.get('event'):
            comparison['differences'].append({
                'field': 'event',
                'android': android_event,
                'current': current_parser_result.get('event'),
                'note': 'Android only has press/release, no hold detection'
            })
    
    return comparison
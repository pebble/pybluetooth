from enum import Enum


class HCIErrorCode(Enum):
    success = 0x00
    unknown_hci_command = 0x01
    unknown_connection_id = 0x02
    hardware_failure = 0x03
    page_timeout = 0x04
    authentication_failure = 0x05
    pin_or_key_missing = 0x06
    memory_capacity_exceeded = 0x07
    connection_timeout = 0x08
    connection_limit_exceeded = 0x09
    synchronous_connection_limit_exceeded = 0x0a
    acl_connection_already_exists = 0x0b
    command_disallowed = 0x0c
    connection_rejected_due_to_limited_resources = 0x0d
    connection_rejected_due_to_bd_addr = 0x0e

    connection_accept_timeout_exceeded = 0x10
    unsupported_feature_or_parameter_value = 0x11
    invalid_hci_command_parameters = 0x12
    remote_user_terminated_connection = 0x13
    remote_device_terminated_connection_due_to_low_resources = 0x14
    remote_device_terminated_connection_due_to_power_off = 0x15
    connection_terminated_by_local_host = 0x16

    lmp_response_timeout = 0x22

    instant_passed = 0x28

    connection_terminated_due_to_mic_failure = 0x3d
    connection_failed_to_be_established = 0x3e




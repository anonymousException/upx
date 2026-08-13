// Repetitive AArch64 NOP code keeps the fixture's payload after DT_INIT.
// UPX may compress executable bytes but must preserve pre-init read-only data.
    .section .text.fixture_payload, "ax", %progbits
    .p2align 2
    .global custom_upx_fixture_payload
    .type custom_upx_fixture_payload, %function
custom_upx_fixture_payload:
    .rept 65536
    nop
    .endr
    ret
    .size custom_upx_fixture_payload, . - custom_upx_fixture_payload

    .section .note.GNU-stack, "", %progbits

#!/usr/bin/env python3
"""
Provenance infrastructure tests (alias analysis Steps 1+).

Step 1: tests _ptr_is_server_response() and _SERVER_RESPONSE_STRUCTS.

Exit code: 0 if all pass, 1 if any fail.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bounds_checker.parsers.taint_scanner import (
    _ptr_is_server_response,
    _SERVER_RESPONSE_STRUCTS,
)


def run():
    bad = 0
    total = 0

    def check(label, got, want):
        nonlocal bad, total
        total += 1
        if got == want:
            print(f'.  {label}')
        else:
            print(f'FAIL  {label}: expected {want!r}, got {got!r}')
            bad += 1

    # ── _ptr_is_server_response: response-only types → True ────────────
    check('smb2_read_rsp',
          _ptr_is_server_response('rsp', {'rsp': 'smb2_read_rsp'}), True)
    check('smb2_negotiate_rsp',
          _ptr_is_server_response('nr', {'nr': 'smb2_negotiate_rsp'}), True)
    check('smb2_oplock_break',
          _ptr_is_server_response('ob', {'ob': 'smb2_oplock_break'}), True)
    check('smb2_transform_hdr',
          _ptr_is_server_response('th', {'th': 'smb2_transform_hdr'}), True)
    check('smb2_posix_info',
          _ptr_is_server_response('pi', {'pi': 'smb2_posix_info'}), True)
    check('smb2_symlink_err_rsp',
          _ptr_is_server_response('se', {'se': 'smb2_symlink_err_rsp'}), True)

    # ── Dual-use types excluded (type alone is not sufficient) ──────────
    check('smb2_hdr excluded (dual-use)',
          _ptr_is_server_response('hdr', {'hdr': 'smb2_hdr'}), False)
    check('smb2_pdu excluded (dual-use)',
          _ptr_is_server_response('pdu', {'pdu': 'smb2_pdu'}), False)

    # ── Non-server-response types → False ───────────────────────────────
    check('cifs_tcon → False',
          _ptr_is_server_response('tcon', {'tcon': 'cifs_tcon'}), False)
    check('cifs_ses → False',
          _ptr_is_server_response('ses', {'ses': 'cifs_ses'}), False)
    check('unknown type → False',
          _ptr_is_server_response('x', {'x': 'totally_unknown_struct'}), False)

    # ── Absent from map → False (conservative) ──────────────────────────
    check('empty map → False',
          _ptr_is_server_response('rsp', {}), False)
    check('key absent → False',
          _ptr_is_server_response('rsp', {'other': 'smb2_read_rsp'}), False)

    # ── Every _rsp name in the table resolves to True ───────────────────
    rsp_types = sorted(t for t in _SERVER_RESPONSE_STRUCTS if t.endswith('_rsp'))
    for t in rsp_types:
        check(f'{t} in table', _ptr_is_server_response('v', {'v': t}), True)

    # ── Table sanity: no dual-use names ────────────────────────────────
    dual_use = {'smb2_hdr', 'smb2_pdu', 'smb_hdr', 'smb_t2_rsp'}
    for name in dual_use:
        check(f'{name} absent from table',
              name in _SERVER_RESPONSE_STRUCTS, False)

    print(f'\n{total - bad} pass, {bad} fail')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(run())

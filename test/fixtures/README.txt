Throwaway self-signed certificate for router.test.invalid, used ONLY by
test/connection_test.dart (local TLS server on 127.0.0.1). Not a secret,
not used anywhere else.

home_link_request.json: the Windows home link request (Dart -> cvwg.dll ->
elevated helper), checked by test/vpn_modes_windows_test.dart and by
native/cvwg/winvpn/protocol_test.go so both sides agree on the field names.
The "keys" are the byte sequences 1..32, 33..64 and 65..96 - not real keys.

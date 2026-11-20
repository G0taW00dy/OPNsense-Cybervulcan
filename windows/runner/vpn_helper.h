#ifndef RUNNER_VPN_HELPER_H_
#define RUNNER_VPN_HELPER_H_

// Cybervulcan "home link": when the exe is started with --vpn-helper (by the
// tray app, through the UAC prompt) it runs the elevated helper from cvwg.dll
// instead of the Flutter UI. Returns true and sets |exit_code| in that case.
bool RunVpnHelperIfRequested(int* exit_code);

#endif  // RUNNER_VPN_HELPER_H_

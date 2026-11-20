#include "vpn_helper.h"

#include <windows.h>
#include <shellapi.h>

#include <string>

bool RunVpnHelperIfRequested(int* exit_code) {
  int argc = 0;
  wchar_t** argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
  if (argv == nullptr) {
    return false;
  }
  const bool requested = argc >= 2 && std::wstring(argv[1]) == L"--vpn-helper";
  ::LocalFree(argv);
  if (!requested) {
    return false;
  }

  // Load cvwg.dll by full path from the exe's own folder (never the search
  // path: this process runs elevated). The helper validates its arguments
  // itself.
  *exit_code = 10;
  wchar_t exe[MAX_PATH * 4];
  const DWORD n = ::GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
  if (n == 0 || n >= ARRAYSIZE(exe)) {
    return true;
  }
  std::wstring dll(exe, n);
  const size_t slash = dll.find_last_of(L"\\/");
  if (slash == std::wstring::npos) {
    return true;
  }
  dll = dll.substr(0, slash + 1) + L"cvwg.dll";
  HMODULE lib = ::LoadLibraryExW(dll.c_str(), nullptr,
                                 LOAD_WITH_ALTERED_SEARCH_PATH);
  if (lib == nullptr) {
    *exit_code = 11;
    return true;
  }
  using HelperMain = int (*)();
  auto helper_main =
      reinterpret_cast<HelperMain>(::GetProcAddress(lib, "cvvpn_helper_main"));
  if (helper_main == nullptr) {
    *exit_code = 12;
    return true;
  }
  *exit_code = helper_main();
  return true;
}

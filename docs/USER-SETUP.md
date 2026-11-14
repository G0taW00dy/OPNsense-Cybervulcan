# Cybervulcan - setting up the app on your device

Cybervulcan shows what the home router is doing (which VPN exit the house
uses, failover, kill switch) and lets you switch the whole-house VPN bypass
on and off. The router admin sets up the router; you only need this page.

## What you get from the admin

* A **settings file or text** (or a QR code) - no passwords in it.
* Your own **API key and secret** (the two lines `key=` and `secret=`).
  Keep them private.

## Install

* **Android:** install `Cybervulcan-x.y.z.apk` from the GitHub release (allow
  "Install unknown apps" for your browser or file manager when asked).
* **Windows:** run `Cybervulcan-Setup-x.y.z.exe` (no admin rights needed).

## First start

The app opens a short setup:

1. **Welcome** - press **Load settings from admin...** and paste the text or
   open the file. This fills in the router address, the certificate name and
   everything else.
2. **Router** - normally already filled in: address `10.10.10.254` and
   certificate name `router.cybervulcan.com`. The app connects to the address
   and checks that the router's certificate carries that name. If it does
   not, the app shows **"Wrong certificate - not your router"** and never
   sends your key.
3. **API key** - paste your key and secret. They are kept in the phone's /
   PC's secure storage and only ever sent to the router.
4. **Test connection** - only works at home. Every line should say OK
   (lines marked "optional" may fail if the admin did not give you that
   permission - that's fine).
5. **Remote access (optional)** - to use the app away from home:
   * Press **Generate key**, then **Copy** (or **QR**) and send the
     **public key** to the admin. It is safe to share; the private part
     never leaves your device.
   * The admin tells you your **tunnel address** (e.g. `10.10.99.3/32`) if it
     was not in the settings.
   * Make sure **"Use remote access when the router is not reachable"** is on.
   * If the admin sent a pre-shared key, paste it and press **Store**.
6. **Done** - **Save and start**.

Remote access works next to a VPN app such as Proton VPN: it is not a system
VPN and only the Cybervulcan app uses it.

## Everyday use

* **Status** shows the VPN exit and health. "Not home" means the router did
  not answer (and remote access is off or not set up yet).
* **Whole-house VPN bypass** takes *everyone at home* off the VPN for a set
  time - you are always asked first.
* **Windows:** closing the window keeps Cybervulcan running in the tray
  (next to the clock). Right-click the tray icon > **Quit** to exit.
* **Android:** add the home-screen widget or the "VPN bypass" Quick Settings
  tile if you like. The widget only works at home.

## If something is wrong

| Message | What to do |
|---|---|
| Wrong certificate - not your router | At home: tell the admin. Elsewhere: another network uses the same address; with remote access set up the app goes through the tunnel instead. |
| Not home - remote access failed | Check you sent your public key to the admin and the tunnel address is right. |
| API key/secret rejected | Re-enter them in Settings, or ask for a new key. |
| Missing a privilege | Your key may not do that - ask the admin if you need it. |
| Plain http:// warning | The router is still on a test setup; tell the admin. |

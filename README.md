# Kantoor TARS — deploy

## Wat upload je naar je GitHub-repo

Plaats deze bestanden in dezelfde map (root van je Pages-deployment):

```
/
├── index.html                 (de app)
├── manifest.json              (PWA-config)
├── icon.svg                   (vector logo — scaalt overal)
├── icon-32.png                (browser-tab fallback)
├── icon-192.png               (PWA standaard)
├── icon-512.png               (PWA hoog, splash-screen)
├── apple-touch-icon.png       (iOS home-screen)
├── favicon.ico                (oudere browsers, Windows)
└── service-worker.js          (optioneel — alleen als je 'm hebt)
```

## Installeren op je telefoon

Na deployen naar GitHub Pages:

**iPhone (Safari):**
1. Open de URL in Safari
2. Tap deelknop (vierkant met pijl omhoog) → "Zet op beginscherm"
3. App verschijnt met TARS-icoon, opent fullscreen zonder browser-UI

**Android (Chrome):**
1. Open de URL in Chrome
2. Menu (⋮) → "App installeren" of "Toevoegen aan beginscherm"
3. Verschijnt als losse app, opstartscherm met paper-cream achtergrond

**Desktop (Chrome, Edge):**
1. Klik installeer-icoon in adresbalk (rechts, plusje of monitor-icoon)
2. App krijgt eigen venster

## Welke kleuren / branding

- `theme_color` en `background_color` zijn beide **#F4F1EA** (paper cream)
- iOS-statusbalk past zich aan, Android-splash-screen ook
- Geen extra config nodig

## Pas aan na deployment

Als je later het logo wilt veranderen — bewerk `icon.svg`, hergenereer de PNGs (cairosvg of via een online tool als realfavicongenerator.net) en commit.

Verander je app-naam? Update `name` en `short_name` in `manifest.json`. `short_name` is wat onder het icoon op het beginscherm staat (max ~12 chars).

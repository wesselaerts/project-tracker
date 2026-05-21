# Allico → Kantoor TARS sync — setup

Plak het snippet onderaan vóór `</body>` in je Allico `index.html`. Allico pusht dan automatisch zijn sessies naar de Cloudflare Worker, en Kantoor TARS leest daar.

---

## Stap 1 — Worker upgrade

Upload de nieuwe `cloudflare-worker.js` (v8) naar je Cloudflare dashboard → **Deploy**.

Voeg dan toe in **Settings → Variables and Secrets**:
- `ALLICO_DATA_API_KEY` (type: **Secret**) = zelfgekozen lange random string, bv. `allico_xK2mPq8nL4vR7tWeF3aBcD9hY5zM6jN1`

Check via `https://forge-c2-proxy6.<jouwnaam>.workers.dev/health` dat `"allicoDataExport": true` staat.

---

## Stap 2 — Vind je Allico session-storage key

Open Allico in je browser, druk **F12** (DevTools) → **Console** tab → typ:

```javascript
Object.keys(localStorage).filter(k => k.toLowerCase().includes('stat') || k.toLowerCase().includes('mcx') || k.toLowerCase().includes('quiz') || k.toLowerCase().includes('session'))
```

Druk Enter. Je ziet bv. `['mcx-quiz-stats']` of `['mcx_stats']`. Dat is je key.

Test dat sessies erin staan met:

```javascript
JSON.parse(localStorage.getItem('mcx-quiz-stats'))
```

Je moet een object zien met een `sessions`-array (of vergelijkbaar) erin, met elk sessie-object dat ten minste een `timestamp` of `date` heeft.

**Noteer je STATS_KEY en de array-naam** (vaak `sessions`, soms `history` of `attempts`).

---

## Stap 3 — Plak dit snippet onderaan Allico's `index.html`

Net vóór de afsluitende `</body>` tag:

```html
<script>
// === Kantoor TARS sync — pusht sessies bij elke save ===
(function() {
  const WORKER_URL = 'https://forge-c2-proxy6.<JOUWNAAM>.workers.dev';
  const STATS_KEY = 'mcx-quiz-stats';   // <-- vervang als jouw key anders is (zie Stap 2)
  const SESSIONS_FIELD = 'sessions';     // <-- naam van de array binnen stats (bv. 'sessions', 'history', 'attempts')

  async function pushAllico() {
    try {
      const raw = localStorage.getItem(STATS_KEY);
      if (!raw) return;
      const stats = JSON.parse(raw);
      const rawSessions = Array.isArray(stats[SESSIONS_FIELD]) ? stats[SESSIONS_FIELD] : [];

      // Voeg per sessie een ISO date toe op basis van timestamp (zodat Kantoor TARS makkelijk per dag kan tellen)
      const sessions = rawSessions.map(s => {
        const ts = s.timestamp ?? s.time ?? s.date ?? s.endedAt ?? s.completedAt;
        let date = null;
        if (typeof ts === 'number') {
          date = new Date(ts).toISOString().slice(0, 10);
        } else if (typeof ts === 'string') {
          date = ts.slice(0, 10);
        }
        return { ...s, date };
      }).filter(s => s.date);

      await fetch(WORKER_URL + '/allico-data/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessions })
      });
    } catch (e) {
      console.warn('Allico sync failed:', e);
    }
  }

  // Sync bij elke localStorage write op de stats-key
  const _setItem = localStorage.setItem.bind(localStorage);
  localStorage.setItem = function(key, value) {
    _setItem(key, value);
    if (key === STATS_KEY) {
      setTimeout(pushAllico, 100);
    }
  };

  // Initial sync bij page load (na 2s zodat app eerst inlaadt)
  setTimeout(pushAllico, 2000);

  // Sync wanneer tab focus krijgt (catch-up als je net hebt geoefend)
  window.addEventListener('focus', () => setTimeout(pushAllico, 200));
})();
</script>
```

Vervang in dit snippet:
- `<JOUWNAAM>` met je Cloudflare Worker subdomein
- `STATS_KEY` met wat je in Stap 2 vond
- Eventueel `SESSIONS_FIELD` als de array niet `sessions` heet

Commit + push naar GitHub Pages.

---

## Stap 4 — Kantoor TARS configureren

Open Kantoor TARS → **Instellingen** → scroll naar **Allico — leer-oefenen**:

- **API key**: zelfde string als `ALLICO_DATA_API_KEY` in stap 1
- **Doel per dag**: 3 (of wat je wilt)
- Druk **test koppeling** — moet `gekoppeld ✓ — X sessies totaal, vandaag Y` geven

---

## Stap 5 — Verificatie

Open Allico, doe één korte sessie (klik door een paar vragen). Bij de save zou er automatisch een sync moeten plaatsvinden. Open Kantoor TARS → ga naar Agenda → onderaan vandaag's dagblok zie je:

```
Allico                    1/3
```

Doe nog twee sessies, sync opnieuw, en je ziet:

```
Allico · doel gehaald ✓    3/3   (groen)
```

---

## Wat TARS er nu mee doet

Bij elke chat krijgt TARS dit in zijn context:

```
ALLICO LEER-OEFENEN (kwiz-app voor tentamen-voorbereiding):
- Daggoal: 3 sessies
- Vandaag: 2/3
- Deze week: 14 sessies totaal, 4/7 dagen doel gehaald
- Huidige streak: 3 dagen op rij doel gehaald
```

Dus bij je maandag-briefing of als je vraagt *"hoe staat het ervoor?"*, kan TARS opmerkingen maken zoals:
- *"Streak van 5 dagen — vasthouden."*
- *"3 dagen gemist deze week. Patroon: vrijdag/zaterdag mist altijd. Verplaatsen naar ochtend?"*
- *"Vandaag 0/3 — eerste sessie nu doen voordat je begint met de rest."*

---

## Troubleshooting

**Sessies komen niet binnen in Kantoor TARS** → Open Allico in DevTools → Console — kijk of er een rode error verschijnt over de fetch. Meest waarschijnlijk: verkeerd WORKER_URL of STATS_KEY in het snippet.

**`401 UNAUTHORIZED` bij test koppeling** → API key in Kantoor TARS-instellingen matcht niet met de Worker secret. Strict identiek vereist.

**`API_KEY_NOT_CONFIGURED`** → `ALLICO_DATA_API_KEY` ontbreekt in Worker secrets. Stap 1 niet voltooid of nog niet deployed.

**Aantal sessies blijft op 0 terwijl je net hebt geoefend** → Het snippet werkt alleen als Allico zijn stats via `localStorage.setItem(STATS_KEY, ...)` opslaat. Als Allico iets als IndexedDB gebruikt voor stats, moet de hook anders. Geef in dat geval de exacte naam van de functie die in Allico sessies opslaat, dan kan ik 'n alternatief schrijven.

**Sessies van vóór de sync zijn niet zichtbaar** → Bij eerste sync wordt de hele localStorage stats array opgestuurd, dus oude sessies komen mee mits ze in dezelfde array staan. Check via `/allico-data/status` (geen auth nodig) hoe veel sessies de Worker heeft ontvangen.

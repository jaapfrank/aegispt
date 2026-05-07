# Frontend Framework Evaluatie & Migratiestrategie

## 1. Huidige Situatie
De huidige frontend van AegisPT (gelegen in de `ui/` folder) is gebouwd met **Vanilla JavaScript**.
Uit analyse van de codebase blijkt dat specifieke modules enorm groot zijn geworden:
*   `ui/assets/modules/wizard.js` (~7.300 regels code)
*   `ui/assets/modules/mission-control.js` (~8.700 regels code)

Deze bestanden bevatten momenteel complexe logica voor state-management (via een gedeelde `state` en `patchState` in `runtime.js`), string-gebaseerde HTML-rendering (via template literals) en zware DOM-manipulaties. Dit patroon is lastig te onderhouden, foutgevoelig (XSS-risico's bij onjuiste escaping) en maakt het lastig om componenten te hergebruiken.

## 2. Framework Opties voor Stapsgewijze Migratie

Om de complexiteit te verminderen, is een migratie naar een modern component-gebaseerd framework noodzakelijk. Omdat het systeem al operationeel is, heeft een **stapsgewijze (incremental) migratie** de voorkeur boven een 'big bang' rewrite.

### Optie A: Vue.js (Aanbevolen voor stapsgewijze migratie)
Vue.js is van oudsher ontworpen om progressief te worden geadopteerd.
*   **Voordelen:** Kan direct via een CDN-script in de huidige `index.html` worden geladen. Specifieke DOM-elementen (bijv. `<section id="screen-wizard">`) kunnen als aparte Vue-apps worden gemount ('Island architecture'). Het integreert relatief makkelijk met de bestaande globale `state` via Vue's reactivity system.
*   **Nadelen:** Als het project later naar een volledige SPA (Single Page Application) gaat, is alsnog een bundler (Vite) en een build-stap nodig.

### Optie B: React.js
React is de industriestandaard en heeft het grootste ecosysteem.
*   **Voordelen:** Enorme hoeveelheid beschikbare componenten en libraries. Uitstekend voor zeer complexe state-management scenario's.
*   **Nadelen:** Stapsgewijze adoptie in een Vanilla JS app zonder build-tooling is omslachtig (o.a. vanwege JSX compilatie). Dit vereist vrijwel direct de introductie van Vite of Webpack, wat impact heeft op de huidige deployment.

### Optie C: Svelte
Svelte compileert componenten naar sterk geoptimaliseerde Vanilla JS.
*   **Voordelen:** Geen Virtual DOM (zeer hoge performance), zeer schone en leesbare syntax. Ideaal voor het verkleinen van de bundelgrootte (huidige `.js` files zijn enorm). Svelte componenten kunnen gecompileerd worden naar Web Components (Custom Elements) en direct in de huidige HTML gebruikt worden.
*   **Nadelen:** De adoptie als "drop-in" in bestaande HTML zonder build-stap is onmogelijk; een bundler is direct vereist.

## 3. Conclusie & Aanbeveling

**Aanbeveling: Vite + Vue 3 (Composition API) of Svelte (als Web Components)**

Gezien de behoefte om stapsgewijs te migreren zonder de bestaande lay-out (`app-shell` in `index.html`) onmiddellijk te breken, raden we aan om **Vue 3** te gebruiken in combinatie met **Vite** voor de build-stap.

### Voorgesteld Migratieplan (Stapsgewijs)

**Fase 1: Tooling Introductie**
1.  Voeg een `package.json` toe in de `ui/` directory.
2.  Installeer **Vite** en **Vue**.
3.  Configureer Vite om de bestaande Vanilla JS bestanden te bundelen als startpunt, zonder de werking aan te passen.

**Fase 2: State Management Brug**
1.  Wikkel de huidige `patchState` en globale `state` (uit `runtime.js`) in een Vue `reactive()` object of Pinia store, zodat zowel de oude Vanilla JS als de nieuwe Vue componenten naar dezelfde waarheid (state) kijken.

**Fase 3: Isolatie & Migratie van de Wizard (Pilot)**
1.  Converteer `wizard.js` (het meest complexe formulier) naar een set van kleine Vue Single File Components (SFCs).
2.  Mount de nieuwe Vue `<WizardApp />` in de bestaande `<section id="screen-wizard">` in `index.html`.
3.  Test grondig via de bestaande Playwright tests.

**Fase 4: Mission Control & Voltooiing**
1.  Zodra de Wizard stabiel draait in Vue, pakken we `mission-control.js` aan. Dit component bevat veel live data (SSE feeds, status updates). Vue's reactivity is hier perfect voor.
2.  Migreer kleinere modules (`dashboard.js`, `settings.js`).
3.  Verwijder langzaamaan alle Vanilla JS template-literal renders en oude state-handlers.

## Volgende stappen
*   Bespreken van deze keuze met het team.
*   Fase 1 (Vite tooling) inrichten op een aparte branch om de impact op de huidige CI/CD pijplijn te valideren.
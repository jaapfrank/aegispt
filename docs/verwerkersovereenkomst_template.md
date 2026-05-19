# Verwerkersovereenkomst Template Voor AegisPT Assessments

Last updated: 2026-04-28

Dit template is bedoeld als startpunt voor Nederlandse/EU AegisPT-dienstverlening. Laat het juridisch beoordelen en pas het aan op de concrete opdracht, partijen, landen, subverwerkers en beveiligingsmaatregelen.

## 1. Partijen

Deze verwerkersovereenkomst is gesloten tussen:

- Verwerkingsverantwoordelijke: `[naam klant]`, gevestigd te `[plaats]`, ingeschreven bij de Kamer van Koophandel onder nummer `[nummer]`.
- Verwerker: `[naam dienstverlener/operator]`, gevestigd te `[plaats]`, ingeschreven bij de Kamer van Koophandel onder nummer `[nummer]`.

De verwerker gebruikt AegisPT uitsluitend voor de uitvoering van de overeengekomen beveiligingsassessment(s) binnen de door de verwerkingsverantwoordelijke goedgekeurde scope.

## 2. Onderwerp En Duur

De verwerking vindt plaats voor de duur van de opdracht, inclusief de overeengekomen bewaartermijn voor assessmentdata en rapportages. De standaard bewaartermijn in AegisPT is 90 dagen per engagement, tenzij partijen schriftelijk een andere termijn afspreken.

## 3. Doel Van De Verwerking

De verwerking heeft uitsluitend tot doel:

- het uitvoeren van geautoriseerde beveiligingstests;
- het vastleggen van bewijs, bevindingen, risico's en hersteladvies;
- het genereren en delen van rapportages;
- het ondersteunen van auditability, kwaliteitscontrole en opdrachtverantwoording.

De verwerker mag de gegevens niet voor eigen doeleinden gebruiken.

## 4. Categorieen Persoonsgegevens

Afhankelijk van de scope kan AegisPT de volgende gegevens verwerken:

- IP-adressen, hostnames, domeinnamen, URL's en poorten;
- gebruikersnamen, e-mailachtige accountnamen, LDAP/AD-objectnamen en groepsnamen;
- service banners, productnamen, versies en configuratie-indicatoren;
- kwetsbaarheidsdetails, bewijsreferenties, ernst, status en hersteladvies;
- run-, taak-, tool- en auditmetadata;
- metadata over secret references, zonder ruwe wachtwoorden, tokens, hashes of vault pointers in exports.

## 5. Categorieen Betrokkenen

De verwerking kan betrekking hebben op:

- medewerkers en beheerders van de verwerkingsverantwoordelijke;
- testaccounts en technische accounts;
- klanten, leveranciers of eindgebruikers voor zover hun gegevens voorkomen in de geteste systemen;
- natuurlijke personen die indirect aan IP-adressen of accountnamen gekoppeld kunnen zijn.

## 6. Instructies

De verwerker verwerkt persoonsgegevens uitsluitend op basis van gedocumenteerde instructies van de verwerkingsverantwoordelijke, waaronder:

- de goedgekeurde scope en rules of engagement;
- toegestane testdiepte en autorisatieniveau;
- bewaartermijn;
- rapportage- en exportafspraken;
- eventuele beperkingen voor externe integraties.

Als een instructie volgens de verwerker in strijd is met toepasselijke wetgeving, meldt de verwerker dit zonder onredelijke vertraging aan de verwerkingsverantwoordelijke.

## 7. Geheimhouding

De verwerker zorgt dat personen die toegang hebben tot assessmentdata gebonden zijn aan passende geheimhouding en alleen toegang krijgen voor zover noodzakelijk voor de uitvoering van de opdracht.

## 8. Technische En Organisatorische Maatregelen

De verwerker treft passende maatregelen, waaronder minimaal:

- self-hosted of contractueel goedgekeurde hosting;
- engagement-scoped toegangsbeheer waar beschikbaar;
- auditlogging voor export, cleanup, purge en relevante systeemacties;
- secret materialization via de bestaande veilige runtime-binding flow;
- uitsluiting van ruwe credential material uit data exports;
- typed confirmation voor onomkeerbare purge;
- scheiding tussen assessmentdata, audittrail en capability-pack provenance;
- versleuteling of vault-opslag voor direct ingevoerde secrets waar geconfigureerd;
- periodieke review van retentie-instellingen;
- veilige overdracht van rapportages en exports.

## 9. Subverwerkers

Standaard gebruikt AegisPT geen subverwerkers voor lokaal opgeslagen assessmentdata wanneer het platform self-hosted draait.

Eventuele optionele subverwerkers moeten vooraf worden vastgelegd, bijvoorbeeld:

| Subverwerker | Doel | Locatie | Status |
| --- | --- | --- | --- |
| `[bijv. OpenAI]` | optionele AI-analyse | `[regio]` | alleen indien ingeschakeld |
| `[bijv. Jira/Atlassian]` | issue handoff | `[regio]` | alleen indien gekoppeld |
| `[bijv. externe vault]` | secret opslag | `[regio]` | alleen indien gekoppeld |

De verwerker informeert de verwerkingsverantwoordelijke vooraf over beoogde wijzigingen in subverwerkers, zodat bezwaar mogelijk is.

## 10. Internationale Doorgifte

Doorgifte buiten de EER vindt alleen plaats indien daarvoor een geldige grondslag bestaat, zoals een adequaatheidsbesluit, passende waarborgen of Standard Contractual Clauses. Self-hosted gebruik zonder externe integraties leidt standaard niet tot internationale doorgifte door AegisPT zelf.

## 11. Datalekken

De verwerker meldt een inbreuk in verband met persoonsgegevens zonder onredelijke vertraging aan de verwerkingsverantwoordelijke nadat de verwerker kennis heeft genomen van de inbreuk.

De melding bevat voor zover bekend:

- aard van de inbreuk;
- betrokken systemen en categorieen gegevens;
- vermoedelijke gevolgen;
- genomen of voorgestelde maatregelen;
- contactpunt voor opvolging;
- relevante audit- of logginginformatie.

De verwerkingsverantwoordelijke blijft verantwoordelijk voor eventuele melding aan de Autoriteit Persoonsgegevens en betrokkenen.

## 12. Rechten Van Betrokkenen

De verwerker ondersteunt de verwerkingsverantwoordelijke redelijkerwijs bij verzoeken rond inzage, rectificatie, verwijdering, beperking, overdraagbaarheid en bezwaar. AegisPT ondersteunt dit met engagement data export, retentie-instellingen en hard purge met audittrail.

## 13. Verwijdering En Teruggave

Na afloop van de opdracht verwijdert of retourneert de verwerker de persoonsgegevens conform de schriftelijke instructie van de verwerkingsverantwoordelijke, tenzij wettelijke bewaarplichten anders vereisen.

Voor AegisPT geldt:

- data export kan worden gebruikt voor teruggave;
- retentie cleanup voert soft-delete uit op verlopen run data;
- hard purge verwijdert assessmentdata onomkeerbaar na typed confirmation;
- audit events en minimale engagement/accountability records kunnen worden bewaard voor bewijs van uitvoering en verwijdering.

## 14. Audit En Informatieplicht

De verwerker stelt informatie beschikbaar die redelijkerwijs nodig is om naleving van deze overeenkomst aan te tonen. Dit kan bestaan uit:

- relevante AegisPT audit events;
- data processing inventory;
- retentie- en purgebewijs;
- technische/organisatorische maatregelen;
- rapportage over gebruikte subverwerkers en integraties.

Audits vinden plaats met redelijke aankondiging, binnen normale werktijden, en zonder de veiligheid of vertrouwelijkheid van andere klanten te schaden.

## 15. Aansprakelijkheid En Rangorde

Aansprakelijkheid volgt de hoofdovereenkomst, tenzij partijen schriftelijk anders afspreken. Bij strijdigheid tussen deze verwerkersovereenkomst en de hoofdovereenkomst geldt voor verwerking van persoonsgegevens deze verwerkersovereenkomst, tenzij dwingend recht anders bepaalt.

## 16. Ondertekening

Ondertekend namens de verwerkingsverantwoordelijke:

Naam:

Functie:

Datum:

Handtekening:

Ondertekend namens de verwerker:

Naam:

Functie:

Datum:

Handtekening:

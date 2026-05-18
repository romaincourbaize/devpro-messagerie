# devpro-messagerie

Système de messagerie P2P sécurisée. Les messages sont chiffrés de bout en bout entre les clients — le serveur route des octets qu'il ne peut pas lire.

Trois services :
- **server** — relay WebSocket + interface web
- **mailer** — envoi d'e-mails via SMTP
- **monitor** — surveillance de disponibilité du relay

---

## Prérequis

- [Docker](https://www.docker.com/) et Docker Compose
- _Pour le développement local uniquement_ : Go 1.22+

---

## Installation

```bash
git clone <url-du-repo>
cd devpro-messagerie
cp .env.example .env
```

Ouvrir `.env` et renseigner les identifiants SMTP (voir section [Configuration](#configuration)).

---

## Démarrage

### Avec Docker (recommandé)

```bash
docker compose up --build          # démarre tous les services (foreground)
docker compose up --build -d       # démarre en arrière-plan
docker compose down                # arrête tout
docker compose logs -f             # affiche les logs en temps réel
docker compose down -v             # repart de zéro (supprime la clé Noise — nouvelle identité serveur)
```

### En local (server uniquement)

```bash
cd server
go run .          # lance le relay en mode debug
go test -race ./... # lance les tests avec le race detector
```

---

## Configuration

Copier `.env.example` en `.env` et remplir les valeurs :

| Variable | Description | Exemple |
|---|---|---|
| `MAILER_SMTP_HOST` | Adresse du serveur SMTP | `smtp-relay.brevo.com` |
| `MAILER_SMTP_PORT` | Port SMTP (`587` = STARTTLS, `465` = TLS) | `587` |
| `MAILER_SMTP_USER` | Identifiant SMTP | `compte@brevo.com` |
| `MAILER_SMTP_PASS` | Mot de passe SMTP | `xsmtpsib-...` |
| `MAILER_FROM` | Adresse expéditrice des e-mails | `relay@example.com` |
| `MONITOR_EMAIL_TO` | Adresse destinataire des alertes | `admin@example.com` |

Variables optionnelles du relay (valeurs par défaut suffisantes en dev) :

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_ADDR` | `:8080` | Adresse d'écoute |
| `RELAY_KEY_FILE` | `server.key` | Chemin de la clé Noise (générée si absente) |
| `RELAY_LOG_LEVEL` | `info` | Niveau de log (`debug`, `info`, `warn`, `error`) |

---

## Endpoints

### Server (`localhost:8080`)

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/` | Interface web de chat |
| `WebSocket` | `/ws` | Connexion peer (handshake Noise XX + messagerie) |
| `GET` | `/healthz` | Sonde de disponibilité — répond `200 ok` |

### Mailer (`localhost:8025`, interne)

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/send` | Envoie un e-mail |

Corps de la requête :
```json
{
  "to": "destinataire@example.com",
  "subject": "Sujet",
  "body": "Contenu du message"
}
```

---

## Fonctionnement

1. **User 1** ouvre `http://localhost:8080` dans son navigateur — un ID unique lui est attribué automatiquement (son fingerprint, visible en haut de l'interface)
2. **User 2** fait de même sur `http://localhost:8080` depuis un autre onglet ou navigateur
3. User 1 communique son ID à User 2 (copier-coller, partage manuel)
4. User 2 colle l'ID de User 1 dans le champ destinataire et se connecte
5. Les deux peuvent désormais échanger des messages. Le relay les achemine sans jamais lire leur contenu

---

## Structure du projet

```
server/     relay WebSocket (Go)
mailer/     service e-mail SMTP (Go, stdlib pure)
monitor/    surveillance + alertes (Go, stdlib pure)
```

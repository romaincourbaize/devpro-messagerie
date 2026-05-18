# Analyse architecturale

## 1. Contexte du projet

Système de messagerie **P2P sécurisée** : un relay WebSocket sert de serveur de signalisation. Les clients s'authentifient mutuellement, puis échangent des messages chiffrés de bout en bout. Le relay ne voit jamais les contenus applicatifs — il route des octets opaques.

Trois services composent le système :

| Service | Rôle | Technologie |
|---|---|---|
| `server/` | Relay WebSocket + handshake Noise XX | Go |
| `mailer/` | Envoi d'e-mails transactionnels via SMTP | Go (stdlib pure) |
| `monitor/` | Polling de disponibilité + alertes e-mail | Go (stdlib pure) |

---

## 2. Style architectural retenu

### 2.1 Niveau macro : **Micro-services**

En appliquant le tableau de synthèse du cours :

| Critère | Mono. | Modul. | Distrib. | Services | **Micro-s.** | Ce projet |
|---|---|---|---|---|---|---|
| Déployables | 1 | 1 | Plusieurs | Plusieurs | **Plusieurs** | 3 (server, mailer, monitor) |
| Frontières | Implicites | Explicites | Variables | Contrats | **Strictes** | Strictes (pas de code partagé) |
| ACID natif | Oui | Oui | Non | Non | **Non** | Non (pas de base partagée) |
| Scalabilité | Uniforme | Uniforme | Sélective | Sélective | **Sélective** | Sélective |
| Complexité ops | Faible | Faible | Élevée | Élevée | **Très élevée** | Absorbée par Makefile + Docker Compose |
| Taille d'équipe | 1–5 | 3–15 | 5–20 | 10+ | **10+/domaine** | **1 — tension assumée** |

Les trois services ne partagent rien : pas de code commun, pas de base de données, pas de modèle. Ils se parlent uniquement via HTTP (`POST /send`, `GET /healthz`). Ce sont des frontières strictes, ce qui les distingue du style SOA où les services partagent encore des contrats ou des bibliothèques communes.

---

### 2.2 Niveau micro : **Modulaire avec inspiration hexagonale**

L'architecture hexagonale s'applique à l'intérieur d'un service, pas entre les services. C'est exactement la structure interne de `server/` :

```
pkg/protocol/    ← port : contrat (types de messages, wire format)
internal/noise/  ← adapter : couche crypto (Noise XX encapsulée)
internal/hub/    ← domaine : registre des pairs, routage
internal/handler/← adapter entrant : lifecycle WebSocket
main.go          ← composition root : assemblage des dépendances
```

Le domaine (`hub/`) ne connaît ni WebSocket, ni JSON, ni cryptographie. Il travaille uniquement avec des fingerprints et des enveloppes binaires. Conséquence directe : `hub_test.go` et `handler_test.go` sont indépendants — le domaine se teste sans connexion réseau, les adapters se testent séparément.

---

## 3. Langage choisi : **Go**

### 3.1 Justification par le domaine

Ce projet exploite ce modèle de manière centrale. Le `Hub` (`internal/hub/hub.go`) est un event loop sur channel unique :

```go
for {
    select {
    case ev := <-h.register:    // ajout d'un pair
    case ev := <-h.unregister:  // suppression d'un pair
    case ev := <-h.route:       // routage d'un message
    case <-h.quit:              // arrêt propre
    }
}
```

Toutes les mutations du registre passent par cette goroutine. La map `peers` n'est accessible que depuis lui. Il n'y a aucun mutex : les données ne sont pas partagées, elles transitent par des channels.

### 3.2 Go dans le projet

| Ce que Go force à penser (cours) | Où c'est visible dans le code |
|---|---|
| **Qui possède quoi** | `client.Send` est écrit par le hub, lu par `writeLoop` — propriété explicite |
| **Les erreurs sont des valeurs** | Chaque couche propage son erreur ; aucune exception silencieuse |
| **Les interfaces sont structurelles** | `handler` dépend de `*hub.Hub` sans mot-clé `implements` |

### 3.3 Alternatives rejetées

- **Node.js** : Node.js ne fait qu'une chose à la fois. Pendant qu'il chiffre pour un client, tous les autres doivent attendre. Go n'a pas ce problème : chaque connexion tourne dans son propre goroutine, en parallèle.

- **Python** : Python a une contrainte interne (le GIL) qui l'empêche de vraiment paralléliser du calcul. Pour un relay qui doit gérer beaucoup de connexions simultanées avec du chiffrement, c'est rédhibitoire.

- **Rust** : Rust offre des garanties de sécurité mémoire très fortes, mais au prix d'une courbe d'apprentissage importante. Pour ce projet, Go est largement suffisant.

---

## 4. Communication entre services

Le cours distingue deux modes de communication selon le **couplage temporel** :

| Mode | Quand l'utiliser |
|---|---|
| **Synchrone** | Quand le résultat est nécessaire immédiatement pour continuer |
| **Asynchrone** | Quand les systèmes ont des cycles de vie indépendants |

Les deux patterns coexistent dans ce projet :

- **`monitor` → `server`** (`GET /healthz`) : **synchrone**. Le monitor a besoin de la réponse immédiatement pour décider si le service est en vie.
- **`monitor` → `mailer`** (`POST /send`) : **synchrone mais tolérant à l'échec**. L'alerte e-mail n'est pas critique pour le fonctionnement du relay. Si le mailer est indisponible, le monitor continue sans planter.
- **`client` → `server` → `client`** (WebSocket + Noise) : **asynchrone au niveau applicatif** — le relay dépose le message dans le channel du destinataire et répond à l'expéditeur sans attendre que le destinataire ait lu.

---

## 5. Synthèse - Les trois questions 

**1. Quel problème spécifique ce langage et cette architecture résolvent-ils dans ce projet ?**

Le relay doit gérer des connexions WebSocket concurrentes. Le modèle CSP de Go (goroutines + channels) permet de traiter chaque connexion dans son propre goroutine sans partage de mémoire, avec un event loop central sans mutex. Ce n'est pas réalisable sans dégradation sur Node.js (single-thread CPU-bound) ni sur Python (GIL).

**2. Pourquoi pas les alternatives principales ?**

- Node.js : bloqué par le CPU-bound sur un event loop single-thread.
- Python : GIL incompatible avec du parallélisme CPU réel.
- Monolithe modulaire : le monitor ne peut pas surveiller de l'extérieur un processus dont il fait partie.

**3. Quels compromis avez-vous assumés ?**

- Micro-services pour un développeur seul : complexité opérationnelle réelle, compensée par la séparation légitime des cycles de vie.
- Hub in-memory : pas de persistance des messages en transit, cohérent avec le modèle P2P.
- Frontend Vanilla JS : pas de typage statique côté client, acceptable pour un projet backend-first.

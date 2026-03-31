# Roadmap — Prototype OS-G (focus Memory Warden)

Objectif : rendre la vision testable rapidement, sans tout construire.

## Phase 0 — Spécifier et mesurer
- Définir un micro-scope : allocation pages, zones, capabilities.
- Définir 5 invariants non négociables (sécurité + isolation).

## Phase 1 — Base Rust `no_std`
- Runtime minimal (panic handler, alloc error handler).
- Structures de base : bitmap/buddy allocator.

## Phase 2 — Zones + per‑CPU cache
- Zones mémoire (critique / driver / app / sandbox).
- Fast-path per‑CPU (slab simple) pour latence.

## Phase 3 — Capabilities
- Table de capabilities (handle opaque).
- Vérifs R/W/X, quotas, TTL.
- Délégation contrôlée (sous-capabilities).

## Phase 4 — SandRAM + Observabilité (COMPLETED)
- [x] SandRAM pour acteurs suspects (Zones physiques distinctes).
- [x] Journaling des intents mémoire (Journal ring-buffer).
- [x] Sentinel Réactive (Auto-quarantaine après 3 violations).
- [x] Début de replay déterministe (dplus_replay + simulation sentinel).

## Phase 5 — Auto-réparation (COMPLETED)
- [x] Snapshot métadonnées + rollback (`snapshot/restore` + helper transactionnel).
- [x] Expiration automatique des caps d’une cellule crashée (`crash_cell` + reclaim).

## Phase 6 — Policy “BPF-like” (COMPLETED)
- [x] Petit bytecode de policy + verifier (stack bornée, pas de boucles).
- [x] Intégration au Warden (`allocate()` peut deny / force sandbox).
- [x] Chargement depuis D+ (`@@WARDEN:POLICY`).

## Phase 7 — IA (optionnel) (COMPLETED)
- [x] Modèle simple (heuristiques) pour suggérer une pré-allocation.
- [x] Config via D+ (`@@CORTEX:HEUR`) + démo UEFI/QEMU.
- [x] Remplaçable par ML/LLM plus tard, sans casser les garanties.

## Après (hors-scope immédiat, mais aligné vision)
- **D+ Weaver** : faire de D+ un tisseur polyglotte (blocs taggés → IR commune) en gardant un vérificateur strict sur les zones critiques.
- **Spine** : barrière “réflexe” entre le Soma (code brut) et le Warden (lois), pour empêcher un crash matériel.
- **Akasha** : objets immuables + overlays + régénération (remplacer la notion de fichiers/dossiers).
- **Telepathic Link** : délégation/migration multi‑machines (conscience de flotte).

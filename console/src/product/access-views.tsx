import { Cable, KeyRound, Link2, LockKeyhole, Server, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import { operationErrorMessage } from "./errors";
import type {
  AssociationSummary,
  ConsoleStatus,
  GeneratedLocalSecrets,
  PairingInput,
} from "./models";
import { nativeConsole } from "./native";

export function LocalAccessView({
  status,
  failure,
  onStatus,
  onFailure,
}: {
  status: ConsoleStatus | null;
  failure: string | null;
  onStatus: (status: ConsoleStatus) => void;
  onFailure: (message: string | null) => void;
}) {
  const [phrase, setPhrase] = useState("");
  const [generated, setGenerated] = useState<GeneratedLocalSecrets | null>(null);
  const [phraseConfirmation, setPhraseConfirmation] = useState("");
  const [recoveryConfirmation, setRecoveryConfirmation] = useState("");
  const [confirmedCopies, setConfirmedCopies] = useState(false);
  const [busy, setBusy] = useState(false);

  async function prepare() {
    setBusy(true);
    onFailure(null);
    try {
      if (generated) {
        await nativeConsole.discardPreparation(generated.generation_id);
      }
      setGenerated(await nativeConsole.prepare());
      setPhraseConfirmation("");
      setRecoveryConfirmation("");
      setConfirmedCopies(false);
    } catch (error: unknown) {
      onFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function confirmInitialization() {
    if (!generated) return;
    const submittedPhrase = phraseConfirmation;
    const submittedRecovery = recoveryConfirmation;
    setPhraseConfirmation("");
    setRecoveryConfirmation("");
    setBusy(true);
    onFailure(null);
    try {
      onStatus(
        await nativeConsole.confirmInitialization(
          generated.generation_id,
          submittedPhrase,
          submittedRecovery,
          confirmedCopies,
        ),
      );
      setGenerated(null);
    } catch (error: unknown) {
      onFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function unlock() {
    const submitted = phrase;
    setPhrase("");
    setBusy(true);
    onFailure(null);
    try {
      onStatus(await nativeConsole.unlock(submitted));
    } catch (error: unknown) {
      onFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="yc-access yc-stack" aria-labelledby="access-title">
      <div>
        <p className="yc-wordmark">Your Cloud</p>
        <h1 id="access-title">Accès local</h1>
        <p className="yc-muted">La phrase déverrouille uniquement le coffre de cet appareil.</p>
      </div>
      {failure ? (
        <Banner icon={ShieldAlert} title="Accès refusé" tone="danger">
          <p>{failure}</p>
        </Banner>
      ) : null}
      {status?.lock_state === "uninitialized" || !status ? (
        <Card raised>
          <div className="yc-stack">
            <h2>Créer le coffre</h2>
            {generated ? (
              <>
                <p>Conservez ces deux secrets hors ligne. Ils ne seront plus affichés.</p>
                <h3>Phrase de déverrouillage</h3>
                <div className="yc-secret yc-mono">{generated.unlock_phrase}</div>
                <h3>Code de récupération global</h3>
                <div className="yc-secret yc-mono">{generated.recovery_code}</div>
                <Field id="confirm-unlock-phrase" label="Ressaisir la phrase" help="Six mots, séparés par un espace.">
                  <TextInput
                    id="confirm-unlock-phrase"
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    value={phraseConfirmation}
                    onChange={(event) => setPhraseConfirmation(event.target.value)}
                    aria-describedby="confirm-unlock-phrase-help"
                  />
                </Field>
                <Field id="confirm-recovery-code" label="Ressaisir le code de récupération">
                  <TextInput
                    id="confirm-recovery-code"
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    value={recoveryConfirmation}
                    onChange={(event) => setRecoveryConfirmation(event.target.value)}
                  />
                </Field>
                <label className="yc-cluster">
                  <input
                    type="checkbox"
                    checked={confirmedCopies}
                    onChange={(event) => setConfirmedCopies(event.target.checked)}
                  />
                  <span>J’ai conservé deux copies hors ligne du code de récupération.</span>
                </label>
                <div className="yc-cluster">
                  <Button
                    intent="primary"
                    icon={KeyRound}
                    disabled={!phraseConfirmation || !recoveryConfirmation || !confirmedCopies}
                    loading={busy}
                    onClick={() => void confirmInitialization()}
                  >
                    Confirmer et créer le coffre
                  </Button>
                  <Button disabled={busy} onClick={() => void prepare()}>
                    Régénérer
                  </Button>
                </div>
              </>
            ) : (
              <Button intent="primary" icon={KeyRound} loading={busy} onClick={() => void prepare()}>
                Générer les secrets locaux
              </Button>
            )}
          </div>
        </Card>
      ) : (
        <Card raised>
          <form
            className="yc-stack"
            onSubmit={(event) => {
              event.preventDefault();
              void unlock();
            }}
          >
            <Field id="unlock-phrase" label="Phrase de déverrouillage" help="Six mots, séparés par un espace.">
              <TextInput
                id="unlock-phrase"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={phrase}
                onChange={(event) => setPhrase(event.target.value)}
                aria-describedby="unlock-phrase-help"
              />
            </Field>
            <Button type="submit" intent="primary" icon={LockKeyhole} disabled={!phrase} loading={busy}>
              Déverrouiller
            </Button>
          </form>
        </Card>
      )}
    </main>
  );
}

export function InfrastructuresView({
  associations,
  onSelect,
  onPair,
  onCreate,
}: {
  associations: AssociationSummary[];
  onSelect: (association: AssociationSummary) => void;
  onPair: () => void;
  onCreate: () => void;
}) {
  return (
    <div className="yc-stack">
      <header className="yc-page-header">
        <div>
          <h1>Infrastructures</h1>
          <p className="yc-muted">Chaque association conserve ses propres identité, origine et session.</p>
        </div>
        <div className="yc-cluster">
          <Button intent="primary" icon={Link2} onClick={onCreate}>
            Créer une infrastructure
          </Button>
          <Button icon={Link2} onClick={onPair}>
            Associer
          </Button>
        </div>
      </header>
      {associations.length === 0 ? (
        <Card>
          <h2>Aucune infrastructure associée</h2>
          <p>Ouvrez une fenêtre locale sur le Controller pour créer la première association.</p>
        </Card>
      ) : (
        <div className="yc-card-grid">
          {associations.map((association) => (
            <Card key={association.infrastructure_id} className="yc-infrastructure-card">
              <div className="yc-cluster">
                <Server className="yc-icon" aria-hidden="true" />
                <h2>{association.infrastructure_label ?? "Infrastructure non nommée"}</h2>
              </div>
              <div className="yc-mono">{association.infrastructure_id}</div>
              <Badge tone={association.device_status === "active" ? "success" : "danger"} icon={Cable}>
                Appareil {association.device_status === "active" ? "actif" : "non actif"}
              </Badge>
              <div className="yc-infrastructure-card__actions">
                <Button onClick={() => onSelect(association)}>Ouvrir</Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export function AssociationView({
  mode,
  onCancel,
  onComplete,
}: {
  mode: PairingInput["mode"];
  onCancel: () => void;
  onComplete: (association: AssociationSummary) => void;
}) {
  const [input, setInput] = useState<PairingInput>({
    mode,
    origin: "",
    temporary_origin: "",
    controller_id: "",
    infrastructure_id: "",
    server_ca_pem: "",
    server_spki_sha256: "",
    window_id: "",
    window_code: "",
    recovery_code: "",
  });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  function update(name: keyof PairingInput, value: string) {
    setInput((current) => ({ ...current, [name]: value }));
  }

  async function submit() {
    setBusy(true);
    setFailure(null);
    try {
      onComplete(await nativeConsole.pair(input));
      setInput((current) => ({ ...current, window_code: "", recovery_code: "" }));
    } catch (error: unknown) {
      setInput((current) => ({ ...current, window_code: "", recovery_code: "" }));
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="yc-stack">
      <header>
        <h1>Association ou récupération</h1>
        <p className="yc-muted">Recopiez uniquement la feuille affichée par l’autorité locale du Controller.</p>
      </header>
      {failure ? (
        <Banner icon={ShieldAlert} title="Association refusée" tone="danger">
          <p>{failure}</p>
        </Banner>
      ) : null}
      <Card>
        <form
          className="yc-stack"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <Field id="pair-origin" label="Origine principale HTTPS">
            <TextInput id="pair-origin" value={input.origin} onChange={(event) => update("origin", event.target.value)} />
          </Field>
          <Field id="pair-temporary-origin" label="Origine temporaire HTTPS">
            <TextInput
              id="pair-temporary-origin"
              value={input.temporary_origin}
              onChange={(event) => update("temporary_origin", event.target.value)}
            />
          </Field>
          <Field id="pair-controller-id" label="Identifiant du Controller">
            <TextInput
              id="pair-controller-id"
              className="yc-input yc-mono"
              value={input.controller_id}
              onChange={(event) => update("controller_id", event.target.value)}
            />
          </Field>
          <Field id="pair-infrastructure-id" label="Identifiant de l’infrastructure">
            <TextInput
              id="pair-infrastructure-id"
              className="yc-input yc-mono"
              value={input.infrastructure_id}
              onChange={(event) => update("infrastructure_id", event.target.value)}
            />
          </Field>
          <Field id="pair-spki" label="Empreinte SPKI SHA-256">
            <TextInput
              id="pair-spki"
              className="yc-input yc-mono"
              value={input.server_spki_sha256}
              onChange={(event) => update("server_spki_sha256", event.target.value)}
            />
          </Field>
          <Field id="pair-ca" label="Autorité TLS serveur">
            <textarea
              id="pair-ca"
              className="yc-input yc-textarea yc-mono"
              value={input.server_ca_pem}
              onChange={(event) => update("server_ca_pem", event.target.value)}
              spellCheck={false}
            />
          </Field>
          <Field id="pair-window-id" label="Identifiant de fenêtre">
            <TextInput
              id="pair-window-id"
              className="yc-input yc-mono"
              value={input.window_id}
              onChange={(event) => update("window_id", event.target.value)}
            />
          </Field>
          <Field id="pair-window-code" label="Code temporaire">
            <TextInput
              id="pair-window-code"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={input.window_code}
              onChange={(event) => update("window_code", event.target.value)}
            />
          </Field>
          <Field id="pair-recovery-code" label="Code de récupération global">
            <TextInput
              id="pair-recovery-code"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={input.recovery_code}
              onChange={(event) => update("recovery_code", event.target.value)}
            />
          </Field>
          <div className="yc-cluster">
            <Button intent="primary" icon={Link2} type="submit" loading={busy}>
              Vérifier et associer
            </Button>
            <Button onClick={onCancel}>Annuler</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

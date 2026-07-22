import { AlertTriangle, CheckCircle2, Clock3, KeyRound, LockKeyhole, LogOut, RefreshCw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import { operationErrorMessage } from "./errors";
import type {
  AssociationSummary,
  PreparedPhraseChange,
  PreparedRecoveryRotation,
  RecoveryRotationProgress,
} from "./models";
import { nativeConsole } from "./native";

export function ProfileView({
  association,
  recoveryRotation,
  rotating,
  onRotate,
  onRecoveryRotation,
  onLogout,
  onRecover,
}: {
  association: AssociationSummary | null;
  recoveryRotation: RecoveryRotationProgress | null;
  rotating: boolean;
  onRotate: () => void;
  onRecoveryRotation: (progress: RecoveryRotationProgress | null) => void;
  onLogout: () => Promise<void>;
  onRecover: () => void;
}) {
  return (
    <div className="yc-stack">
      <header>
        <h1>Profil et sessions</h1>
        <p className="yc-muted">Le coffre est local ; chaque Controller conserve une session et une identité séparées.</p>
      </header>
      <Card>
        <h2>Coffre local</h2>
        <Badge tone="success" icon={LockKeyhole}>Déverrouillé</Badge>
      </Card>
      <PhraseChangePanel />
      {association ? (
        <Card>
          <div className="yc-stack">
            <h2>Session sélectionnée</h2>
            <dl className="yc-definition-list">
              <dt>Infrastructure</dt>
              <dd className="yc-mono">{association.infrastructure_id}</dd>
              <dt>Appareil</dt>
              <dd>{association.device_status === "active" ? "Actif" : "Non actif"}</dd>
              <dt>Certificat</dt>
              <dd className="yc-mono">{association.certificate_expires_at ?? "Échéance indisponible"}</dd>
            </dl>
            <CertificateExpiryWarning expiresAt={association.certificate_expires_at} />
            <Button icon={LogOut} onClick={() => void onLogout()}>Fermer la session</Button>
            <Button icon={KeyRound} loading={rotating} onClick={onRotate}>Renouveler le certificat d’appareil</Button>
            <Button intent="danger" icon={AlertTriangle} onClick={onRecover}>Lancer une récupération</Button>
          </div>
        </Card>
      ) : (
        <Card>
          <p>Sélectionnez une infrastructure pour consulter son appareil et sa session.</p>
        </Card>
      )}
      <RecoveryRotationPanel progress={recoveryRotation} onProgress={onRecoveryRotation} />
    </div>
  );
}

function PhraseChangePanel() {
  const [prepared, setPrepared] = useState<PreparedPhraseChange | null>(null);
  const [currentPhrase, setCurrentPhrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [completed, setCompleted] = useState(false);

  async function prepare() {
    setBusy(true);
    setFailure(null);
    setCompleted(false);
    try {
      setPrepared(await nativeConsole.preparePhraseChange());
      setCurrentPhrase("");
      setConfirmation("");
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (!prepared) return;
    const submittedCurrent = currentPhrase;
    const submittedNext = confirmation;
    setCurrentPhrase("");
    setConfirmation("");
    setBusy(true);
    setFailure(null);
    try {
      await nativeConsole.confirmPhraseChange(prepared.generation_id, submittedCurrent, submittedNext);
      setPrepared(null);
      setCompleted(true);
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2>Phrase de déverrouillage</h2>
          <p className="yc-muted">Le remplacement rechiffre seulement le coffre local et ne change aucune identité de Controller.</p>
        </div>
        {failure ? (
          <Banner icon={ShieldAlert} title="Phrase inchangée" tone="danger">
            <p>{failure}</p>
          </Banner>
        ) : null}
        {completed ? (
          <Banner icon={CheckCircle2} title="Phrase remplacée" tone="accent">
            <p>Le nouveau coffre a été validé puis publié atomiquement.</p>
          </Banner>
        ) : null}
        {!prepared ? (
          <Button icon={KeyRound} loading={busy} onClick={() => void prepare()}>
            Générer une nouvelle phrase
          </Button>
        ) : (
          <>
            <p>Conservez la nouvelle phrase hors ligne avant de confirmer.</p>
            <div className="yc-secret yc-mono">{prepared.new_unlock_phrase}</div>
            <Field id="current-unlock-phrase" label="Phrase actuelle">
              <TextInput
                id="current-unlock-phrase"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={currentPhrase}
                onChange={(event) => setCurrentPhrase(event.target.value)}
              />
            </Field>
            <Field id="confirm-new-unlock-phrase" label="Ressaisir la nouvelle phrase">
              <TextInput
                id="confirm-new-unlock-phrase"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </Field>
            <div className="yc-cluster">
              <Button
                intent="primary"
                icon={KeyRound}
                loading={busy}
                disabled={!currentPhrase || !confirmation}
                onClick={() => void confirm()}
              >
                Remplacer la phrase
              </Button>
              <Button disabled={busy} onClick={() => void prepare()}>
                Régénérer
              </Button>
            </div>
          </>
        )}
      </div>
    </Card>
  );
}

function CertificateExpiryWarning({ expiresAt }: { expiresAt: string | null }) {
  if (!expiresAt) return null;
  const remainingMilliseconds = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(remainingMilliseconds)) {
    return (
      <Banner icon={ShieldAlert} title="Échéance de certificat invalide" tone="danger">
        <p>La réponse du Controller doit être vérifiée avant toute nouvelle opération.</p>
      </Banner>
    );
  }
  const remainingDays = Math.ceil(remainingMilliseconds / 86_400_000);
  if (remainingDays > 30) return null;
  if (remainingDays <= 0) {
    return (
      <Banner icon={ShieldAlert} title="Certificat expiré" tone="danger">
        <p>Une récupération ou un nouvel appairage local est nécessaire.</p>
      </Banner>
    );
  }
  return (
    <Banner
      icon={Clock3}
      title={remainingDays <= 7 ? "Certificat à renouveler avant J-7" : "Certificat à renouveler avant J-30"}
      tone="warning"
    >
      <p>Il reste {remainingDays} jour{remainingDays > 1 ? "s" : ""}. Le renouvellement reste manuel.</p>
    </Banner>
  );
}

function RecoveryRotationPanel({
  progress,
  onProgress,
}: {
  progress: RecoveryRotationProgress | null;
  onProgress: (progress: RecoveryRotationProgress | null) => void;
}) {
  const [prepared, setPrepared] = useState<PreparedRecoveryRotation | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [oldCode, setOldCode] = useState("");
  const [newCode, setNewCode] = useState("");
  const [confirmedCopies, setConfirmedCopies] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const completed = progress?.controllers.every((controller) => controller.status === "completed") ?? false;

  async function prepare() {
    setBusy(true);
    setFailure(null);
    try {
      setPrepared(await nativeConsole.prepareRecoveryKeyRotation());
      setConfirmation("");
      setConfirmedCopies(false);
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (!prepared) return;
    setBusy(true);
    setFailure(null);
    try {
      const next = await nativeConsole.confirmRecoveryKeyRotation(
        prepared.generation_id,
        confirmation,
        confirmedCopies,
      );
      onProgress(next);
      setPrepared(null);
      setConfirmation("");
      setConfirmedCopies(false);
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function resume() {
    setBusy(true);
    setFailure(null);
    try {
      const next = await nativeConsole.resumeRecoveryKeyRotation(oldCode, newCode);
      onProgress(next);
      setOldCode("");
      setNewCode("");
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function finish() {
    setBusy(true);
    setFailure(null);
    try {
      await nativeConsole.completeRecoveryKeyRotation();
      onProgress(null);
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2>Code de récupération global</h2>
          <p className="yc-muted">
            Le remplacement est suivi séparément pour chaque Controller. L’ancien code reste nécessaire tant que tous ne sont pas terminés.
          </p>
        </div>
        {failure ? (
          <Banner icon={ShieldAlert} title="Rotation incomplète" tone="danger">
            <p>{failure}</p>
          </Banner>
        ) : null}
        {!progress && !prepared ? (
          <Button icon={KeyRound} loading={busy} onClick={() => void prepare()}>
            Générer un nouveau code
          </Button>
        ) : null}
        {prepared ? (
          <div className="yc-stack">
            <p>Ce code vise {prepared.target_count} Controller(s). Conservez deux copies hors ligne avant toute mutation.</p>
            <div className="yc-secret yc-mono">{prepared.new_recovery_code}</div>
            <Field id="confirm-new-recovery-code" label="Ressaisir le nouveau code">
              <TextInput
                id="confirm-new-recovery-code"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </Field>
            <label className="yc-cluster">
              <input
                type="checkbox"
                checked={confirmedCopies}
                onChange={(event) => setConfirmedCopies(event.target.checked)}
              />
              <span>J’ai conservé deux copies hors ligne du nouveau code.</span>
            </label>
            <Button
              intent="primary"
              icon={KeyRound}
              loading={busy}
              disabled={!confirmation || !confirmedCopies}
              onClick={() => void confirm()}
            >
              Créer le suivi de rotation
            </Button>
          </div>
        ) : null}
        {progress ? (
          <div className="yc-stack">
            <div className="yc-machine-list">
              {progress.controllers.map((controller) => (
                <div className="yc-machine-button" key={controller.controller_id}>
                  <div>
                    <strong className="yc-mono">{controller.infrastructure_id}</strong>
                    <div className="yc-muted">Époque cible {controller.target_recovery_epoch}</div>
                  </div>
                  <Badge
                    tone={
                      controller.status === "completed"
                        ? "success"
                        : controller.status === "failed"
                          ? "danger"
                          : "warning"
                    }
                  >
                    {controller.status === "completed"
                      ? "Terminé"
                      : controller.status === "failed"
                        ? "Échec"
                        : "En attente"}
                  </Badge>
                </div>
              ))}
            </div>
            {!completed ? (
              <>
                <Field id="old-global-recovery-code" label="Ancien code">
                  <TextInput
                    id="old-global-recovery-code"
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    value={oldCode}
                    onChange={(event) => setOldCode(event.target.value)}
                  />
                </Field>
                <Field id="new-global-recovery-code" label="Nouveau code">
                  <TextInput
                    id="new-global-recovery-code"
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    value={newCode}
                    onChange={(event) => setNewCode(event.target.value)}
                  />
                </Field>
                <Button
                  intent="primary"
                  icon={RefreshCw}
                  loading={busy}
                  disabled={!oldCode || !newCode}
                  onClick={() => void resume()}
                >
                  Continuer Controller par Controller
                </Button>
              </>
            ) : (
              <>
                <Banner icon={CheckCircle2} title="Rotation complète" tone="accent">
                  <p>Tous les Controllers ont confirmé la nouvelle époque.</p>
                </Banner>
                <Button loading={busy} onClick={() => void finish()}>
                  Fermer ce suivi
                </Button>
              </>
            )}
          </div>
        ) : null}
      </div>
    </Card>
  );
}

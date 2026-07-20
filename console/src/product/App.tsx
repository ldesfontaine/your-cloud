import {
  AlertTriangle,
  Boxes,
  Cable,
  CheckCircle2,
  Clock3,
  Cloud,
  Eye,
  KeyRound,
  LayoutDashboard,
  Link2,
  ListTree,
  LockKeyhole,
  LogOut,
  RefreshCw,
  Server,
  ShieldAlert,
  UserRound,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Badge, Banner, Button, Card, Field, LoadingBlock, TextInput } from "../design/primitives";
import type {
  AssociationSummary,
  ConsoleStatus,
  GeneratedLocalSecrets,
  InfrastructureView,
  MachineView,
  MachinesView,
  PairingInput,
  PreparedPhraseChange,
  PreparedRecoveryRotation,
  RecoveryRotationProgress,
  ViewName,
} from "./models";
import { localErrorMessage, NativeOperationError, nativeConsole } from "./native";

type LoadState = "idle" | "loading" | "ready" | "error";

const authenticatedNavigation: ReadonlyArray<{
  view: ViewName;
  label: string;
  icon: typeof LayoutDashboard;
}> = [
  { view: "summary", label: "Synthèse", icon: LayoutDashboard },
  { view: "fleet", label: "Parc", icon: Boxes },
  { view: "observations", label: "Observations", icon: ListTree },
];

function errorMessage(error: unknown): string {
  if (error instanceof NativeOperationError) return localErrorMessage(error.code);
  return localErrorMessage("console_unavailable");
}

export function App() {
  const [status, setStatus] = useState<ConsoleStatus | null>(null);
  const [view, setView] = useState<ViewName>("local-access");
  const [selectedInfrastructure, setSelectedInfrastructure] = useState<string | null>(null);
  const [infrastructure, setInfrastructure] = useState<InfrastructureView | null>(null);
  const [machines, setMachines] = useState<MachinesView | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [failure, setFailure] = useState<string | null>(null);
  const [associationMode, setAssociationMode] = useState<PairingInput["mode"]>("enrollment");
  const requestGeneration = useRef(0);

  const selectedAssociation = useMemo(
    () => status?.associations.find((item) => item.infrastructure_id === selectedInfrastructure) ?? null,
    [selectedInfrastructure, status],
  );

  useEffect(() => {
    let current = true;
    nativeConsole
      .status()
      .then((next) => {
        if (!current) return;
        setStatus(next);
        setView(next.lock_state === "unlocked" ? "infrastructures" : "local-access");
        setLoadState("ready");
      })
      .catch((error: unknown) => {
        if (!current) return;
        setFailure(errorMessage(error));
        setLoadState("error");
      });
    return () => {
      current = false;
    };
  }, []);

  const clearInfrastructureView = useCallback(() => {
    requestGeneration.current += 1;
    setInfrastructure(null);
    setMachines(null);
    setFailure(null);
  }, []);

  const selectInfrastructure = useCallback(
    async (association: AssociationSummary) => {
      await nativeConsole.cancelPendingRequests().catch(() => undefined);
      clearInfrastructureView();
      setSelectedInfrastructure(association.infrastructure_id);
      setView("summary");
    },
    [clearInfrastructureView],
  );

  const loadSelected = useCallback(async () => {
    if (!selectedInfrastructure) return;
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    setLoadState("loading");
    setFailure(null);
    try {
      const [nextInfrastructure, nextMachines] = await Promise.all([
        nativeConsole.readInfrastructure(selectedInfrastructure),
        nativeConsole.readMachines(selectedInfrastructure),
      ]);
      if (generation !== requestGeneration.current) return;
      setInfrastructure(nextInfrastructure);
      setMachines(nextMachines);
      if (nextInfrastructure.label) {
        setStatus((current) =>
          current
            ? {
                ...current,
                associations: current.associations.map((association) =>
                  association.infrastructure_id === selectedInfrastructure
                    ? { ...association, infrastructure_label: nextInfrastructure.label }
                    : association,
                ),
              }
            : current,
        );
      }
      setLoadState("ready");
    } catch (error: unknown) {
      if (generation !== requestGeneration.current) return;
      setFailure(errorMessage(error));
      setLoadState("error");
    }
  }, [selectedInfrastructure]);

  const initializeSelected = useCallback(
    async (label: string) => {
      if (!selectedInfrastructure) return false;
      setLoadState("loading");
      setFailure(null);
      try {
        const next = await nativeConsole.putInfrastructure(selectedInfrastructure, label);
        setInfrastructure(next);
        setStatus((current) =>
          current
            ? {
                ...current,
                associations: current.associations.map((association) =>
                  association.infrastructure_id === selectedInfrastructure
                    ? { ...association, infrastructure_label: next.label }
                    : association,
                ),
              }
            : current,
        );
        setLoadState("ready");
        return true;
      } catch (error: unknown) {
        setFailure(errorMessage(error));
        setLoadState("error");
        return false;
      }
    },
    [selectedInfrastructure],
  );

	const putSelectedMachine = useCallback(
    async (machineId: string, label: string) => {
      if (!selectedInfrastructure) return false;
      setLoadState("loading");
      setFailure(null);
      try {
        await nativeConsole.putMachine(selectedInfrastructure, machineId, label);
        await loadSelected();
        return true;
      } catch (error: unknown) {
        setFailure(errorMessage(error));
        setLoadState("error");
        return false;
      }
    },
    [loadSelected, selectedInfrastructure],
	);

	const rotateSelectedDevice = useCallback(async () => {
		if (!selectedInfrastructure) return;
		setLoadState("loading");
		setFailure(null);
		try {
			const updated = await nativeConsole.rotateDevice(selectedInfrastructure);
			setStatus((current) =>
				current
					? {
							...current,
							associations: current.associations.map((association) =>
								association.infrastructure_id === selectedInfrastructure ? updated : association,
							),
						}
					: current,
			);
			setLoadState("ready");
		} catch (error: unknown) {
			setFailure(errorMessage(error));
			setLoadState("error");
		}
	}, [selectedInfrastructure]);

  useEffect(() => {
    if (selectedInfrastructure && ["summary", "fleet", "observations", "profile"].includes(view)) {
      void loadSelected();
    }
  }, [selectedInfrastructure, view, loadSelected]);

  async function lockConsole() {
    await nativeConsole.cancelPendingRequests().catch(() => undefined);
    await nativeConsole.lock();
    clearInfrastructureView();
    setSelectedInfrastructure(null);
    setStatus((current) => (current ? { ...current, lock_state: "locked" } : current));
    setView("local-access");
  }

  if (loadState === "loading" && !status) {
    return (
      <main className="yc-access yc-stack" aria-labelledby="startup-title">
        <h1 id="startup-title">Your Cloud</h1>
        <LoadingBlock label="Initialisation de la Console" />
      </main>
    );
  }

  if (!status || status.lock_state !== "unlocked") {
    return (
      <LocalAccessView
        status={status}
        failure={failure}
        onStatus={(next) => {
          setStatus(next);
          setFailure(null);
          if (next.lock_state === "unlocked") setView("infrastructures");
        }}
        onFailure={setFailure}
      />
    );
  }

  return (
    <div className="yc-app">
      <aside className="yc-sidebar">
        <p className="yc-wordmark">Your Cloud</p>
        <nav className="yc-sidebar__nav" aria-label="Navigation principale">
          <NavButton
            label="Infrastructures"
            icon={Cloud}
            current={view === "infrastructures" || view === "association"}
            onClick={() => setView("infrastructures")}
          />
          {selectedAssociation
            ? authenticatedNavigation.map((item) => (
                <NavButton
                  key={item.view}
                  label={item.label}
                  icon={item.icon}
                  current={view === item.view}
                  onClick={() => setView(item.view)}
                />
              ))
            : null}
          <NavButton
            label="Profil et sessions"
            icon={UserRound}
            current={view === "profile"}
            onClick={() => setView("profile")}
          />
        </nav>
        <div className="yc-stack">
          {selectedAssociation ? (
            <div>
              <span className="yc-muted">Infrastructure active</span>
              <div>{selectedAssociation.infrastructure_label ?? "Non nommée"}</div>
              <div className="yc-mono">{selectedAssociation.infrastructure_id}</div>
            </div>
          ) : null}
          <Button icon={LockKeyhole} onClick={() => void lockConsole()}>
            Verrouiller
          </Button>
        </div>
      </aside>
      <main className="yc-main">
        <div className="yc-main__inner">
          {failure ? (
            <Banner icon={ShieldAlert} title="Opération refusée" tone="danger">
              <p>{failure}</p>
            </Banner>
          ) : null}
          {view === "infrastructures" ? (
            <InfrastructuresView
              associations={status.associations}
              onSelect={(association) => void selectInfrastructure(association)}
              onPair={() => {
                setAssociationMode("enrollment");
                setView("association");
              }}
            />
          ) : null}
          {view === "association" ? (
            <AssociationView
              mode={associationMode}
              onCancel={() => setView("infrastructures")}
              onComplete={(association) => {
                setStatus((current) =>
                  current
                    ? {
                        ...current,
                        associations: [
                          ...current.associations.filter(
                            (existing) =>
                              existing.infrastructure_id !== association.infrastructure_id &&
                              existing.controller_id !== association.controller_id,
                          ),
                          association,
                        ].sort((left, right) => left.infrastructure_id.localeCompare(right.infrastructure_id)),
                      }
                    : current,
                );
                void selectInfrastructure(association);
              }}
            />
          ) : null}
          {view === "summary" && selectedAssociation ? (
            <SummaryView
              association={selectedAssociation}
              infrastructure={infrastructure}
              machines={machines}
              loading={loadState === "loading"}
              onRefresh={() => void loadSelected()}
              onInitialize={initializeSelected}
            />
          ) : null}
          {view === "fleet" && selectedAssociation ? (
            <FleetView
              machines={machines}
              loading={loadState === "loading"}
              onRefresh={() => void loadSelected()}
              onPutMachine={putSelectedMachine}
            />
          ) : null}
          {view === "observations" && selectedAssociation ? (
            <ObservationsView
              machines={machines}
              loading={loadState === "loading"}
              onRefresh={() => void loadSelected()}
            />
          ) : null}
          {view === "profile" ? (
            <ProfileView
              association={selectedAssociation}
              recoveryRotation={status.recovery_rotation}
              rotating={loadState === "loading"}
              onRotate={() => void rotateSelectedDevice()}
              onRecoveryRotation={(recoveryRotation) =>
                setStatus((current) =>
                  current ? { ...current, recovery_rotation: recoveryRotation } : current,
                )
              }
              onRecover={() => {
                setAssociationMode("recovery");
                setView("association");
              }}
              onLogout={async () => {
                if (!selectedInfrastructure) return;
                await nativeConsole.logout(selectedInfrastructure);
                await lockConsole();
              }}
            />
          ) : null}
        </div>
      </main>
    </div>
  );
}

function NavButton({
  label,
  icon: Icon,
  current,
  onClick,
}: {
  label: string;
  icon: typeof Cloud;
  current: boolean;
  onClick: () => void;
}) {
  return (
    <button className="yc-nav-button" aria-current={current ? "page" : undefined} onClick={onClick}>
      <Icon className="yc-icon" aria-hidden="true" />
      <span>{label}</span>
    </button>
  );
}

function LocalAccessView({
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
      onFailure(errorMessage(error));
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
      onFailure(errorMessage(error));
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
      onFailure(errorMessage(error));
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

function InfrastructuresView({
  associations,
  onSelect,
  onPair,
}: {
  associations: AssociationSummary[];
  onSelect: (association: AssociationSummary) => void;
  onPair: () => void;
}) {
  return (
    <div className="yc-stack">
      <header className="yc-page-header">
        <div>
          <h1>Infrastructures</h1>
          <p className="yc-muted">Chaque association conserve ses propres identité, origine et session.</p>
        </div>
        <Button intent="primary" icon={Link2} onClick={onPair}>
          Associer
        </Button>
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

function AssociationView({
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
      setFailure(errorMessage(error));
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

function SummaryView({
  association,
  infrastructure,
  machines,
  loading,
  onRefresh,
  onInitialize,
}: {
  association: AssociationSummary;
  infrastructure: InfrastructureView | null;
  machines: MachinesView | null;
  loading: boolean;
  onRefresh: () => void;
  onInitialize: (label: string) => Promise<boolean>;
}) {
  const [label, setLabel] = useState("");
  const recent = machines?.machines.filter((machine) => machine.observation_status === "recent").length ?? 0;
  const old = machines?.machines.filter((machine) => machine.observation_status === "old").length ?? 0;
  const absent = machines?.machines.filter((machine) => machine.observation_status === "absent").length ?? 0;
  return (
    <div className="yc-stack">
      <PageHeader title="Synthèse" subtitle={infrastructure?.label ?? association.infrastructure_label ?? "Infrastructure non nommée"} onRefresh={onRefresh} loading={loading} />
      <div className="yc-dashboard">
        <div className="yc-stack">
          {infrastructure && !infrastructure.initialized ? (
            <Card>
              <form
                className="yc-stack"
                onSubmit={(event) => {
                  event.preventDefault();
                  void onInitialize(label).then((completed) => {
                    if (completed) setLabel("");
                  });
                }}
              >
                <div>
                  <h2>Nommer l’infrastructure</h2>
                  <p className="yc-muted">Ce premier libellé devient immuable pour ce Controller.</p>
                </div>
                <Field id="infrastructure-label" label="Libellé">
                  <TextInput
                    id="infrastructure-label"
                    value={label}
                    maxLength={256}
                    required
                    onChange={(event) => setLabel(event.target.value)}
                  />
                </Field>
                <Button intent="primary" type="submit" loading={loading}>Initialiser</Button>
              </form>
            </Card>
          ) : null}
          {machines?.relay_status !== "available" ? <RelayWarning status={machines?.relay_status ?? "unavailable"} /> : null}
          <div className="yc-card-grid">
            <Metric label="Machines attendues" value={machines?.machines.length ?? 0} icon={Server} />
            <Metric label="Observations récentes" value={recent} icon={CheckCircle2} tone="success" />
            <Metric label="Observations anciennes" value={old} icon={Clock3} tone="warning" />
            <Metric label="Sans observation" value={absent} icon={Eye} />
          </div>
        </div>
        <Card>
          <h2>Connexion à cette infrastructure</h2>
          <dl className="yc-definition-list">
            <dt>Controller</dt>
            <dd className="yc-mono">{association.controller_id}</dd>
            <dt>Origine</dt>
            <dd className="yc-mono">{association.origin}</dd>
            <dt>Révision</dt>
            <dd>{infrastructure?.inventory_revision ?? "—"}</dd>
          </dl>
        </Card>
      </div>
    </div>
  );
}

function FleetView({
  machines,
  loading,
  onRefresh,
  onPutMachine,
}: {
  machines: MachinesView | null;
  loading: boolean;
  onRefresh: () => void;
  onPutMachine: (machineId: string, label: string) => Promise<boolean>;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [machineId, setMachineId] = useState("");
  const [label, setLabel] = useState("");
  const selectedMachine = machines?.machines.find((machine) => machine.machine_id === selected) ?? machines?.machines[0] ?? null;
  return (
    <div className="yc-stack">
      <PageHeader title="Parc" subtitle="Machines attendues par cette infrastructure" onRefresh={onRefresh} loading={loading} />
      <Card>
        <form
          className="yc-stack"
          onSubmit={(event) => {
            event.preventDefault();
            void onPutMachine(machineId, label).then((completed) => {
              if (completed) {
                setMachineId("");
                setLabel("");
              }
            });
          }}
        >
          <div>
            <h2>Rattacher ou renommer une machine</h2>
            <p className="yc-muted">Un nouveau rattachement exige que le Relay confirme maintenant une machine enrôlée active.</p>
          </div>
          <div className="yc-form-grid">
            <Field id="machine-id" label="Identifiant machine">
              <TextInput
                id="machine-id"
                className="yc-input yc-mono"
                value={machineId}
                maxLength={63}
                required
                onChange={(event) => setMachineId(event.target.value)}
              />
            </Field>
            <Field id="machine-label" label="Libellé">
              <TextInput
                id="machine-label"
                value={label}
                maxLength={256}
                required
                onChange={(event) => setLabel(event.target.value)}
              />
            </Field>
          </div>
          <Button intent="primary" type="submit" loading={loading}>Confirmer</Button>
        </form>
      </Card>
      {!machines || machines.machines.length === 0 ? (
        <Card>
          <h2>Parc vide</h2>
          <p>Aucune machine n’est encore rattachée à l’inventaire du Controller.</p>
        </Card>
      ) : (
        <div className="yc-dashboard">
          <div className="yc-machine-list">
            {machines.machines.map((machine) => (
              <button
                key={machine.machine_id}
                className="yc-machine-button"
                aria-pressed={selectedMachine?.machine_id === machine.machine_id}
                onClick={() => setSelected(machine.machine_id)}
              >
                <span>
                  <strong>{machine.label}</strong>
                  <span className="yc-mono">{machine.machine_id}</span>
                </span>
                <ObservationBadge status={machine.observation_status} />
              </button>
            ))}
          </div>
          {selectedMachine ? <MachineDetail machine={selectedMachine} /> : null}
        </div>
      )}
    </div>
  );
}

function ObservationsView({ machines, loading, onRefresh }: { machines: MachinesView | null; loading: boolean; onRefresh: () => void }) {
  return (
    <div className="yc-stack">
      <PageHeader title="Observations" subtitle="Dernier instantané courant, sans historique" onRefresh={onRefresh} loading={loading} />
      {machines?.relay_status !== "available" ? <RelayWarning status={machines?.relay_status ?? "unavailable"} /> : null}
      <Card>
        <dl className="yc-definition-list">
          <dt>Instantané Relay</dt>
          <dd className="yc-mono">{machines?.relay_snapshot_at ?? "Aucun instantané validé"}</dd>
          <dt>État du transport</dt>
          <dd>{relayLabel(machines?.relay_status ?? "unavailable")}</dd>
        </dl>
      </Card>
      <div className="yc-desktop-only">
        <Card>
          <table className="yc-table">
            <thead>
              <tr>
                <th>Machine</th>
                <th>Réception UTC</th>
                <th>Séquence</th>
                <th>Continuité</th>
                <th>Fraîcheur</th>
              </tr>
            </thead>
            <tbody>
              {(machines?.machines ?? []).map((machine) => (
                <tr key={machine.machine_id}>
                  <td>{machine.label}</td>
                  <td className="yc-mono">{machine.observation?.received_at ?? "—"}</td>
                  <td>{machine.observation?.sequence ?? "—"}</td>
                  <td>{continuityLabel(machine)}</td>
                  <td><ObservationBadge status={machine.observation_status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
      <div className="yc-mobile-only yc-stack">
        {(machines?.machines ?? []).map((machine) => (
          <MachineDetail key={machine.machine_id} machine={machine} />
        ))}
      </div>
    </div>
  );
}

function ProfileView({
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
      <RecoveryRotationPanel
        progress={recoveryRotation}
        onProgress={onRecoveryRotation}
      />
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
      setFailure(errorMessage(error));
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
      await nativeConsole.confirmPhraseChange(
        prepared.generation_id,
        submittedCurrent,
        submittedNext,
      );
      setPrepared(null);
      setCompleted(true);
    } catch (error: unknown) {
      setFailure(errorMessage(error));
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
      setFailure(errorMessage(error));
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
      setFailure(errorMessage(error));
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
      setFailure(errorMessage(error));
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
      setFailure(errorMessage(error));
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
            <p>
              Ce code vise {prepared.target_count} Controller(s). Conservez deux copies hors ligne avant toute mutation.
            </p>
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

function PageHeader({ title, subtitle, onRefresh, loading }: { title: string; subtitle: string; onRefresh: () => void; loading: boolean }) {
  return (
    <header className="yc-page-header">
      <div>
        <h1>{title}</h1>
        <p className="yc-muted">{subtitle}</p>
      </div>
      <Button icon={RefreshCw} loading={loading} onClick={onRefresh}>Actualiser</Button>
    </header>
  );
}

function Metric({ label, value, icon: Icon, tone = "accent" }: { label: string; value: number; icon: typeof Server; tone?: "accent" | "success" | "warning" }) {
  return (
    <Card>
      <div className="yc-metric">
        <Badge tone={tone} icon={Icon}>{label}</Badge>
        <span className="yc-metric__value">{value}</span>
      </div>
    </Card>
  );
}

function MachineDetail({ machine }: { machine: MachineView }) {
  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2>{machine.label}</h2>
          <div className="yc-mono">{machine.machine_id}</div>
        </div>
        <ObservationBadge status={machine.observation_status} />
        <dl className="yc-definition-list">
          <dt>Enrôlement</dt>
          <dd>{machine.enrollment_status ?? "Indisponible"}</dd>
          <dt>Séquence</dt>
          <dd>{machine.observation?.sequence ?? "—"}</dd>
          <dt>Observation UTC</dt>
          <dd className="yc-mono">{machine.observation?.observed_at ?? "—"}</dd>
          <dt>Réception UTC</dt>
          <dd className="yc-mono">{machine.observation?.received_at ?? "—"}</dd>
          <dt>Continuité</dt>
          <dd>{continuityLabel(machine)}</dd>
        </dl>
        {machine.observation?.observed_time_warning ? (
          <Banner icon={Clock3} title="Horloge de la machine différente" tone="warning">
            <p>La fraîcheur reste calculée depuis l’heure de réception du Relay.</p>
          </Banner>
        ) : null}
      </div>
    </Card>
  );
}

function ObservationBadge({ status }: { status: MachineView["observation_status"] }) {
  switch (status) {
    case "recent":
      return <Badge tone="success" icon={CheckCircle2}>Récente</Badge>;
    case "old":
      return <Badge tone="warning" icon={Clock3}>Ancienne</Badge>;
    case "absent":
      return <Badge icon={Eye}>Absente</Badge>;
    case "untrusted":
      return <Badge tone="danger" icon={ShieldAlert}>Non actualisable</Badge>;
    case null:
      return <Badge icon={Eye}>Indisponible</Badge>;
  }
}

function RelayWarning({ status }: { status: MachinesView["relay_status"] }) {
  const clock = status === "clock_untrusted";
  return (
    <Banner icon={clock ? Clock3 : Cable} title={clock ? "Horloge Relay non fiable" : "Relay indisponible"} tone="warning">
      <p>{clock ? "Le dernier état validé reste visible sans être présenté comme actuel." : "Une panne de transport ne signifie pas que le parc est vide."}</p>
    </Banner>
  );
}

function relayLabel(status: MachinesView["relay_status"]): string {
  if (status === "available") return "Disponible";
  if (status === "clock_untrusted") return "Horloge non fiable";
  return "Indisponible";
}

function continuityLabel(machine: MachineView): string {
  const observation = machine.observation;
  if (!observation) return "Aucune observation";
  if (observation.continuity === "complete") return "Complète";
  const count = observation.gap_summary?.dropped_count ?? 0;
  return `${count} observation${count > 1 ? "s" : ""} manquante${count > 1 ? "s" : ""}`;
}

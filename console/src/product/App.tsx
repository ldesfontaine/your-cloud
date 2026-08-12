import {
  Boxes,
  Cloud,
  LayoutDashboard,
  ListTree,
  LockKeyhole,
  PackageOpen,
  ScrollText,
  ShieldAlert,
  Unplug,
  UserRound,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Banner, Button, LoadingBlock } from "../design/primitives";
import { AssociationView, InfrastructuresView, LocalAccessView } from "./access-views";
import { operationErrorMessage } from "./errors";
import { ExternalView, FleetView, ObservationsView, SummaryView } from "./infrastructure-views";
import { PlansView } from "./plans-view";
import type {
  AssociationSummary,
  ConsoleStatus,
  ExternalElementsView,
  PlanDispatchEntryView,
  InfrastructureView,
  MachinesView,
  PairingInput,
  ServiceDefinitionsProjection,
  ViewName,
} from "./models";
import { nativeConsole } from "./native";
import { ProfileView } from "./profile-view";
import { ServicesView } from "./service-views";

type LoadState = "loading" | "ready" | "error";

const authenticatedNavigation: ReadonlyArray<{
  view: ViewName;
  label: string;
  icon: typeof LayoutDashboard;
}> = [
  { view: "summary", label: "Synthèse", icon: LayoutDashboard },
  { view: "fleet", label: "Parc", icon: Boxes },
  { view: "observations", label: "Observations", icon: ListTree },
  { view: "external", label: "Éléments externes", icon: Unplug },
  { view: "services", label: "Services", icon: PackageOpen },
  { view: "plans", label: "Plans", icon: ScrollText },
];

export function App() {
  const [status, setStatus] = useState<ConsoleStatus | null>(null);
  const [view, setView] = useState<ViewName>("local-access");
  const [selectedInfrastructure, setSelectedInfrastructure] = useState<string | null>(null);
  const [infrastructure, setInfrastructure] = useState<InfrastructureView | null>(null);
  const [machines, setMachines] = useState<MachinesView | null>(null);
  const [external, setExternal] = useState<ExternalElementsView | null>(null);
  const [definitions, setDefinitions] = useState<ServiceDefinitionsProjection | null>(null);
  const [dispatches, setDispatches] = useState<PlanDispatchEntryView[]>([]);
  // Le nom qu'un geste « Déployer » a nommé, et rien d'autre : la vue Plans
  // fait construire la paire par le Controller, elle ne reçoit pas de plan.
  const [deploySlug, setDeploySlug] = useState<string | null>(null);
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
        setFailure(operationErrorMessage(error));
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
    setExternal(null);
    setDefinitions(null);
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
      // Les deux inventaires sont lus ensemble parce qu'ils s'affichent
      // ensemble : ce qui est géré et ce qui est externe se lisent sur le même
      // écran, sous le même mot d'ancienneté.
      const [nextInfrastructure, nextMachines, nextExternal] = await Promise.all([
        nativeConsole.readInfrastructure(selectedInfrastructure),
        nativeConsole.readMachines(selectedInfrastructure),
        nativeConsole.readExternalElements(selectedInfrastructure),
      ]);
      if (generation !== requestGeneration.current) return;
      setInfrastructure(nextInfrastructure);
      setMachines(nextMachines);
      setExternal(nextExternal);
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
      setFailure(operationErrorMessage(error));
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
        setFailure(operationErrorMessage(error));
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
        setFailure(operationErrorMessage(error));
        setLoadState("error");
        return false;
      }
    },
    [loadSelected, selectedInfrastructure],
  );

  // Retirer une déclaration ne retire que la déclaration. La phrase qui le dit
  // est écrite près du bouton qui la confirme ; ici il ne reste qu'un appel et
  // une relecture des deux inventaires.
  const withdrawExternalElement = useCallback(
    async (elementId: string) => {
      if (!selectedInfrastructure) return false;
      setLoadState("loading");
      setFailure(null);
      try {
        await nativeConsole.withdrawExternalElement(selectedInfrastructure, elementId);
        await loadSelected();
        return true;
      } catch (error: unknown) {
        setFailure(operationErrorMessage(error));
        setLoadState("error");
        return false;
      }
    },
    [loadSelected, selectedInfrastructure],
  );

  // Les définitions gelées sont un troisième inventaire, lu à part et sur sa
  // propre révision : geler une définition ne doit pas déplacer la révision
  // contre laquelle la Console tient son parc, et une lecture qui les
  // rassemblerait effacerait cette séparation à l'écran.
  // L'histoire des lancements est lue à part des définitions : l'une dit ce qui
  // est gelé, l'autre ce qui a été lancé, et les mélanger ferait dépendre l'une
  // de la fraîcheur de l'autre.
  const loadDispatches = useCallback(async () => {
    if (!selectedInfrastructure) return;
    try {
      const next = await nativeConsole.readPlanDispatches(selectedInfrastructure);
      setDispatches([...next.dispatches]);
    } catch {
      // L'absence d'histoire n'empêche pas de lire des définitions : la vue
      // dit alors qu'aucun plan portant ce nom n'a été lancé, ce qui est vrai
      // de ce que cette Console peut voir.
      setDispatches([]);
    }
  }, [selectedInfrastructure]);

  const loadDefinitions = useCallback(async () => {
    if (!selectedInfrastructure) return;
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    setLoadState("loading");
    setFailure(null);
    try {
      const next = await nativeConsole.readServiceDefinitions(selectedInfrastructure);
      if (generation !== requestGeneration.current) return;
      setDefinitions(next);
      setLoadState("ready");
    } catch (error: unknown) {
      if (generation !== requestGeneration.current) return;
      setFailure(operationErrorMessage(error));
      setLoadState("error");
    }
  }, [selectedInfrastructure]);

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
      setFailure(operationErrorMessage(error));
      setLoadState("error");
    }
  }, [selectedInfrastructure]);

  useEffect(() => {
    if (
      selectedInfrastructure &&
      // La vue Plans lit le parc elle aussi : la position qu’une machine a
      // rapportée est ce que la signature doit nommer, et une vue qui
      // l’ignorerait signerait une position devinée.
      ["summary", "fleet", "observations", "external", "profile", "plans"].includes(view)
    ) {
      void loadSelected();
    }
  }, [selectedInfrastructure, view, loadSelected]);

  useEffect(() => {
    if (selectedInfrastructure && (view === "services" || view === "plans")) void loadDefinitions();
    if (selectedInfrastructure && (view === "services" || view === "plans")) void loadDispatches();
  }, [selectedInfrastructure, view, loadDefinitions]);

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
              external={external}
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
          {view === "external" && selectedAssociation ? (
            <ExternalView
              external={external}
              loading={loadState === "loading"}
              onRefresh={() => void loadSelected()}
              onWithdraw={withdrawExternalElement}
            />
          ) : null}
          {view === "services" && selectedAssociation ? (
            <ServicesView
              infrastructureId={selectedAssociation.infrastructure_id}
              definitions={definitions}
              dispatches={dispatches}
              loading={loadState === "loading"}
              onRefresh={() => void loadDefinitions()}
              onFroze={() => void loadDefinitions()}
              onDeploy={(slug) => {
                setDeploySlug(slug);
                setView("plans");
              }}
            />
          ) : null}
          {view === "plans" && selectedAssociation ? (
            <PlansView
              infrastructureId={selectedAssociation.infrastructure_id}
              definitions={definitions}
              machines={machines}
              initialSlug={deploySlug}
              onRefresh={() => void loadDefinitions()}
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

import {
  Cable,
  CheckCircle2,
  CircleHelp,
  Clock3,
  Eye,
  Link2Off,
  RefreshCw,
  Server,
  ShieldAlert,
  Unplug,
} from "lucide-react";
import { Fragment, useState } from "react";
import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import type {
  AssociationSummary,
  ExternalElementsView,
  ExternalElementView,
  ExternalKind,
  InfrastructureView,
  MachineView,
  MachinesView,
} from "./models";

export function SummaryView({
  association,
  infrastructure,
  machines,
  external,
  loading,
  onRefresh,
  onInitialize,
}: {
  association: AssociationSummary;
  infrastructure: InfrastructureView | null;
  machines: MachinesView | null;
  external: ExternalElementsView | null;
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
      <PageHeader
        title="Synthèse"
        subtitle={infrastructure?.label ?? association.infrastructure_label ?? "Infrastructure non nommée"}
        onRefresh={onRefresh}
        loading={loading}
      />
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
            {/* Les éléments externes se comptent à côté des machines gérées et
                sous le même mot d’ancienneté : deux seuils, ou deux vocabulaires,
                mettraient deux sens d’« ancien » sur le même écran. */}
            <Metric label="Éléments externes" value={external?.elements.length ?? 0} icon={Unplug} />
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

export function FleetView({
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

export function ObservationsView({
  machines,
  loading,
  onRefresh,
}: {
  machines: MachinesView | null;
  loading: boolean;
  onRefresh: () => void;
}) {
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

// Les quatre absences viennent du contexte de cette route et jamais du fil.
// Elles sont identiques pour toutes les lignes, il n’existe aucun état où elles
// diffèrent, et une Console qui les lirait au lieu de les savoir offrirait une
// action de gestion le jour où un Controller compromis dirait oui.
const EXTERNAL_ABSENCES: ReadonlyArray<{ capability: string; refusal: string }> = [
  { capability: "Mettre à jour", refusal: "non — aucun plan ne décrit cet élément" },
  { capability: "Restaurer", refusal: "non — le produit ne détient aucune de ses données" },
  { capability: "Supprimer", refusal: "non — retirer la déclaration ne retire pas la chose" },
  { capability: "Garantir l’état", refusal: "non — seule une lecture datée est offerte" },
];

export function ExternalView({
  external,
  loading,
  onRefresh,
  onWithdraw,
}: {
  external: ExternalElementsView | null;
  loading: boolean;
  onRefresh: () => void;
  onWithdraw: (elementId: string) => Promise<boolean>;
}) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const elements = external?.elements ?? [];
  return (
    <div className="yc-stack">
      <PageHeader
        title="Éléments externes"
        subtitle="Déclarés depuis une machine enrôlée, jamais posés par ce produit"
        onRefresh={onRefresh}
        loading={loading}
      />
      <Banner icon={Unplug} title="Ce produit ne gère pas ces éléments" tone="accent">
        <p>
          Un élément externe est la parole d’un humain sur une chose que Your Cloud n’a pas
          installée. Aucun plan ne le décrit, et aucune action de gestion n’est offerte ici.
        </p>
        <dl className="yc-definition-list">
          {EXTERNAL_ABSENCES.map((absence) => (
            <Fragment key={absence.capability}>
              <dt>{absence.capability}</dt>
              <dd>{absence.refusal}</dd>
            </Fragment>
          ))}
        </dl>
      </Banner>
      {elements.length === 0 ? (
        <Card>
          <h2>Aucune déclaration externe</h2>
          <p>
            Rien n’est déclaré externe sur cette infrastructure. Un voisin que personne n’a déclaré
            reste inconnu : rien ne le découvre et rien ne le nomme.
          </p>
        </Card>
      ) : (
        <div className="yc-external-list">
          {elements.map((element) => (
            <ExternalElementCard
              key={element.element_id}
              element={element}
              confirming={confirming === element.element_id}
              loading={loading}
              onAsk={() => setConfirming(element.element_id)}
              onKeep={() => setConfirming(null)}
              onConfirm={() => {
                void onWithdraw(element.element_id).then((completed) => {
                  if (completed) setConfirming(null);
                });
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ExternalElementCard({
  element,
  confirming,
  loading,
  onAsk,
  onKeep,
  onConfirm,
}: {
  element: ExternalElementView;
  confirming: boolean;
  loading: boolean;
  onAsk: () => void;
  onKeep: () => void;
  onConfirm: () => void;
}) {
  return (
    <Card>
      <div className="yc-stack">
        <div>
          {/* Le libellé est la parole d’un tiers : rendu comme du texte, borné à
              son cadre et isolé du sens de lecture de la page. Il n’est jamais
              du balisage, jamais une instruction, et il n’élargit rien. */}
          <h2 className="yc-external__label" dir="ltr">
            {element.label}
          </h2>
          <div className="yc-mono yc-external__origin">
            {externalKindLabel(element.kind)} · port {element.probe_port} · {element.machine_id}
          </div>
        </div>
        <div className="yc-cluster">
          <ExternalStateBadge element={element} />
          <ObservationBadge status={element.observation_status} />
        </div>
        <p>{externalReadingSentence(element)}</p>
        {element.state === "verified" && element.observation_status === "old" ? (
          <Banner icon={Clock3} title="Constat ancien" tone="warning">
            <p>
              Ce constat dépasse la limite d’ancienneté annoncée. Il reste vérifié à sa date et
              cesse d’être présenté comme actuel.
            </p>
          </Banner>
        ) : null}
        {element.state === "unverifiable" && element.reason === "port_is_managed" ? (
          <Banner icon={ShieldAlert} title="Déclaration contredite par la machine" tone="warning">
            <p>
              Ce port est tenu par un service que ce produit gère : la déclaration dit externe une
              chose que la machine détient. Elle n’est pas retirée pour autant, parce que retirer
              une déclaration est un acte humain.
            </p>
          </Banner>
        ) : null}
        <dl className="yc-definition-list">
          <dt>Constat</dt>
          <dd className="yc-mono">{element.observed_at ?? "Aucune lecture"}</dd>
          <dt>Ancienneté</dt>
          <dd>{externalAgeLabel(element)}</dd>
          <dt>Déclaré le</dt>
          <dd className="yc-mono">{element.declared_at}</dd>
        </dl>
        {confirming ? (
          <Banner icon={Link2Off} title="Retirer cette déclaration ?" tone="warning">
            <p>
              Le retrait retire la déclaration, et rien d’autre : la chose déclarée continue
              d’exister, continue de détenir ses données et continue de fonctionner. Your Cloud
              cesse seulement de la montrer.
            </p>
            <div className="yc-cluster">
              <Button intent="danger" loading={loading} onClick={onConfirm}>
                Retirer la déclaration
              </Button>
              <Button onClick={onKeep}>Conserver la déclaration</Button>
            </div>
          </Banner>
        ) : (
          <div className="yc-cluster">
            <Button icon={Link2Off} onClick={onAsk}>
              Retirer la déclaration
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

function ExternalStateBadge({ element }: { element: ExternalElementView }) {
  switch (element.state) {
    case "declared":
      return <Badge icon={Eye}>Déclaré</Badge>;
    case "verified":
      return (
        <Badge tone="success" icon={CheckCircle2}>
          Vérifié
        </Badge>
      );
    case "contradicted":
      return (
        <Badge tone="danger" icon={ShieldAlert}>
          Contredit
        </Badge>
      );
    case "unverifiable":
      return (
        <Badge tone="warning" icon={CircleHelp}>
          Invérifiable
        </Badge>
      );
  }
}

// Une phrase par état, et une phrase distincte par motif d’invérifiable :
// « rien n’écoute » et « la machine n’est pas joignable » sont des faits
// différents. « Contredit » dit ce que le contrat lui fait dire — un port qui
// répondait n’accepte plus — et jamais que la chose aurait disparu.
function externalReadingSentence(element: ExternalElementView): string {
  switch (element.state) {
    case "declared":
      return "Déclaré : personne n’a encore constaté cet élément. Le libellé reste la parole de l’humain.";
    case "verified":
      return "Vérifié : à cette date, une lecture a trouvé ce port répondant. Quelque chose répond sur ce port, et rien ne dit que ce soit la chose nommée.";
    case "contradicted":
      return "Contredit : le port qu’une lecture datée avait trouvé répondant n’accepte plus aucune connexion. La machine contredit ce que la déclaration dit s’y trouver.";
    case "unverifiable":
      switch (element.reason) {
        case "nothing_listening":
          return "Invérifiable : rien n’écoute sur ce port, vu depuis cette machine.";
        case "response_too_large":
          return "Invérifiable : la réponse dépasse la borne de lecture, et la lecture n’a rien conclu.";
        case "machine_unreachable":
          return "Invérifiable : la machine qui sert de point de vue n’a rapporté aucune lecture.";
        case "port_is_managed":
          return "Invérifiable : ce port est tenu par un service que ce produit gère, et rien ne s’y est connecté.";
      }
  }
}

// L’ancienneté est calculée par le Controller et lue telle quelle : la Console
// n’a pas d’horloge d’autorité et n’en invente pas une seconde.
function externalAgeLabel(element: ExternalElementView): string {
  switch (element.observation_status) {
    case "absent":
      return "Aucun constat à dater";
    case "recent":
      return "Constat récent";
    case "old":
      return "Constat ancien, plus présenté comme actuel";
  }
}

function externalKindLabel(kind: ExternalKind): string {
  return kind === "external_service" ? "Service externe" : "Passage externe";
}

function PageHeader({
  title,
  subtitle,
  onRefresh,
  loading,
}: {
  title: string;
  subtitle: string;
  onRefresh: () => void;
  loading: boolean;
}) {
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

function Metric({
  label,
  value,
  icon: Icon,
  tone = "accent",
}: {
  label: string;
  value: number;
  icon: typeof Server;
  tone?: "accent" | "success" | "warning";
}) {
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

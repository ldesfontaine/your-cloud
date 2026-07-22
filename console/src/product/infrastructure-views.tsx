import { Cable, CheckCircle2, Clock3, Eye, RefreshCw, Server, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import type { AssociationSummary, InfrastructureView, MachineView, MachinesView } from "./models";

export function SummaryView({
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

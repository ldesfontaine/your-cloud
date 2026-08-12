import { CircleHelp, RefreshCw, ScrollText, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import { operationErrorDetail, operationErrorMessage } from "./errors";
import type {
  PlanConsentSessionView,
  PlanDispatchEntryView,
  PlanDispatchState,
  PlanPairPresentation,
  ServiceDefinitionsProjection,
} from "./models";
import { nativeConsole } from "./native";

// Ce que chaque état d’un dispatch veut dire, en une phrase, et le ton qui va
// avec. « lancé, non rapporté » n’est ni un succès ni un échec : il a son propre
// mot, sa propre teinte, et rien dans cette vue ne le range dans l’un des deux.
// C’est la règle du produit — après une coupure, rendre « résultat inconnu » —
// tenue là où un humain la lit.
const DISPATCH_STATES: Record<PlanDispatchState, { label: string; tone: "neutral" | "success" | "warning" | "danger"; sentence: string }> = {
  in_flight: {
    label: "En cours",
    tone: "neutral",
    sentence: "L’enregistrement est écrit ; le reste est en train de se produire.",
  },
  not_launched: {
    label: "Non lancé",
    tone: "neutral",
    sentence:
      "La connexion a échoué avant le premier octet, et le Controller l’a observé. Aucun effet n’existe.",
  },
  machine_refused: {
    label: "Refusé par la machine",
    tone: "warning",
    sentence: "La machine a refusé et dit pourquoi. Elle n’a rien changé.",
  },
  reported: {
    label: "Rapporté",
    tone: "success",
    sentence: "Un rapport valide a été lu. Il porte la conclusion de la machine.",
  },
  launched_unreported: {
    label: "Lancé, non rapporté",
    tone: "warning",
    sentence:
      "Ce Controller ne sait pas ce que la machine a fait : elle peut avoir agi ou non. Rien n’est rejoué ; observez avant tout nouveau plan.",
  },
};

// Les quatre moments d’un plan, dans l’ordre où un humain les vit. La ligne
// s’arrête au dernier moment réellement atteint : elle ne promet pas la suite.
const JOURNEY: readonly { key: string; label: string }[] = [
  { key: "built", label: "Construit" },
  { key: "approved", label: "Approuvé" },
  { key: "launched", label: "Lancé" },
  { key: "reported", label: "Rapporté" },
];

function reachedStep(state: PlanDispatchState): number {
  switch (state) {
    case "not_launched":
      return 1;
    case "in_flight":
    case "machine_refused":
    case "launched_unreported":
      return 2;
    case "reported":
      return 3;
  }
}

function instant(unixSeconds: number): string {
  if (unixSeconds === 0) return "—";
  return new Date(unixSeconds * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function PlansView({
  definitions,
  infrastructureId,
  initialSlug,
  onRefresh,
}: {
  definitions: ServiceDefinitionsProjection | null;
  infrastructureId: string;
  // Le parc n'est plus reçu ici. La seule valeur que cette vue en tirait — la
  // position que la machine visée a elle-même rapportée — doit dater du moment
  // où la paire est construite, et un parc reçu en propriété date, lui, du
  // dernier changement de vue.
  //
  // Le nom qu'un geste « Déployer » a nommé, s'il y en a eu un. C'est tout ce
  // qui traverse depuis la vue Services : aucun plan, aucun document, aucune
  // empreinte — le Controller construit la paire et cette vue la relit.
  initialSlug: string | null;
  onRefresh: () => void;
}) {
  const [machineId, setMachineId] = useState("");
  const [slug, setSlug] = useState(initialSlug ?? "");
  const [imageDigest, setImageDigest] = useState("");
  const [localPort, setLocalPort] = useState("");
  const [originHost, setOriginHost] = useState("");
  const [pair, setPair] = useState<PlanPairPresentation | null>(null);
  // La position et l’époque de la machine visée, lues au dernier moment qui
  // précède encore la construction de la paire, et tenues avec elle.
  //
  // Le parc reçu en propriété n’est relu qu’au changement de vue : après un
  // lancement, il décrit un monde d’avant. La signature qui suivait nommait
  // alors une position déjà dépassée, et le Controller refusait — ce qui était
  // juste. Le contrat dit que cette Console apprend la position par la vue des
  // machines ; il ne dit pas qu’elle peut l’apprendre une fois pour toutes.
  //
  // Elles sont retenues plutôt que relues au moment de signer, pour deux
  // raisons : ce qui est signé est alors la position lue quand la paire a été
  // construite, et elles restent attachées à la machine pour laquelle cette
  // paire existe, même si le champ du formulaire change ensuite.
  //
  // Résiduel, nommé : entre la construction de la paire et la soumission, une
  // position peut encore bouger. C’est alors une concurrence réelle, bornée par
  // « au plus une approbation gaspillée », et non une péremption systématique.
  const [target, setTarget] = useState<{
    machineId: string;
    reported: number;
    epoch: number;
  } | null>(null);
  const [session, setSession] = useState<PlanConsentSessionView | null>(null);
  const [dispatches, setDispatches] = useState<PlanDispatchEntryView[]>([]);
  const [failure, setFailure] = useState<string | null>(null);
  // Le contrôle qui a refusé, quand le cœur l’a nommé. Il accompagne la phrase
  // plutôt que de la remplacer : « la réponse reçue ne respecte pas le contrat
  // de sécurité » ne dit rien de la suite, et un humain devant cette phrase
  // seule ne peut ni agir ni rapporter ce qu’il a vu.
  const [failureDetail, setFailureDetail] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const polling = useRef<number | null>(null);

  const frozen = definitions?.definitions ?? [];
  const selected = frozen.find((entry) => entry.slug === slug) ?? null;

  const loadDispatches = useCallback(async () => {
    try {
      const view = await nativeConsole.readPlanDispatches(infrastructureId);
      setDispatches([...view.dispatches].reverse());
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
      setFailureDetail(operationErrorDetail(error));
    }
  }, [infrastructureId]);

  useEffect(() => {
    void loadDispatches();
  }, [loadDispatches]);

  // La fenêtre native est un autre processus : cette vue ne sait pas ce qu’elle
  // affiche et n’a aucun moyen de répondre à sa place. Elle demande où en est
  // la session, et rien d’autre.
  useEffect(() => {
    if (!session || session.state === "answered") return;
    const timer = window.setInterval(() => {
      nativeConsole
        .planConsentStatus(session.request_id)
        .then(setSession)
        .catch((error: unknown) => {
          setSession(null);
          setFailure(operationErrorMessage(error));
          setFailureDetail(operationErrorDetail(error));
        });
    }, 500);
    polling.current = timer;
    return () => window.clearInterval(timer);
  }, [session]);

  const readPair = useCallback(async () => {
    setFailure(null);
    setFailureDetail(null);
    setBusy(true);
    try {
      // Le parc et les lancements sont relus ici, avant que le Controller ne
      // construise quoi que ce soit : c’est le dernier moment où la position
      // que la signature nommera peut encore être apprise du produit plutôt
      // que d’un souvenir.
      const [fleet, launched] = await Promise.all([
        nativeConsole.readMachines(infrastructureId),
        nativeConsole.readPlanDispatches(infrastructureId),
      ]);
      // Le plus récent d'abord, comme partout ailleurs dans cette vue : c'est
      // le dernier lancement d'une machine qui porte son époque.
      const recent = [...launched.dispatches].reverse();
      setDispatches(recent);
      const port = Number.parseInt(localPort, 10);
      const presentation = await nativeConsole.readPlanPair(
        infrastructureId,
        machineId,
        "deploy_user_service",
        slug,
        selected?.definition_sha256 ?? "",
        imageDigest,
        Number.isNaN(port) ? 0 : port,
        originHost,
      );
      const machine = fleet.machines.find((entry) => entry.machine_id === machineId) ?? null;
      setTarget({
        machineId,
        reported: machine?.command_position.last_reported_sequence ?? 0,
        epoch: recent.find((entry) => entry.machine_id === machineId)?.approval_epoch ?? 1,
      });
      setPair(presentation);
      setSession(null);
    } catch (error: unknown) {
      setPair(null);
      setTarget(null);
      setFailure(operationErrorMessage(error));
      setFailureDetail(operationErrorDetail(error));
    } finally {
      setBusy(false);
    }
  }, [infrastructureId, machineId, slug, selected, imageDigest, localPort, originHost]);

  const openConsent = useCallback(async () => {
    setFailure(null);
    setFailureDetail(null);
    try {
      setSession(await nativeConsole.openPlanConsent(infrastructureId));
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
      setFailureDetail(operationErrorDetail(error));
    }
  }, [infrastructureId]);

  const cancelConsent = useCallback(async () => {
    if (!session) return;
    try {
      await nativeConsole.cancelPlanConsent(session.request_id);
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
      setFailureDetail(operationErrorDetail(error));
    }
    setSession(null);
  }, [session]);

  // Signer et soumettre, une fois que la fenêtre native a rendu une
  // confirmation. Ce geste est distinct de l’approbation elle-même : la fenêtre
  // dit qu’un humain a lu et accepté ces phrases, et c’est ici seulement que la
  // clé signe et que des octets partent. Rien n’est automatique — un humain
  // clique — parce qu’une soumission qui suivrait la fermeture de la fenêtre
  // ferait de la fenêtre le déclencheur d’un effet, et le contrat en fait un
  // recueil de consentement.
  //
  // L’époque et la position ne sont pas choisies ici : la position est le
  // successeur exact de ce que la machine a elle-même rapporté, et l’époque
  // vient de son dernier lancement rapporté. Une machine dont ce Controller
  // n’atteste rien est à sa première position sous l’époque de son ancre ; si
  // cette supposition est fausse, la machine refuse en nommant sa propre
  // position, cette phrase est montrée sans être réécrite, et le coût est une
  // approbation — exactement la borne que le contrat a écrite.
  //
  // Elles ne sont pas non plus lues ici : elles ont été lues quand cette paire
  // a été construite, et elles sont retenues avec elle. Sans paire retenue, il
  // n’y a aucune position à nommer, donc rien à signer.
  const submitDecision = useCallback(async () => {
    if (!session || !session.confirmed || !target) return;
    setFailure(null);
    setFailureDetail(null);
    setBusy(true);
    try {
      await nativeConsole.submitPlanDecision(
        infrastructureId,
        session.request_id,
        target.epoch,
        target.reported + 1,
      );
      setSession(null);
      setPair(null);
      setTarget(null);
      await loadDispatches();
    } catch (error: unknown) {
      // La session est dépensée côté natif quoi qu’il arrive : une
      // confirmation qui pourrait être soumise deux fois autoriserait deux
      // lancements. La vue le dit plutôt que de laisser un bouton qui rejouera.
      setSession(null);
      setFailure(operationErrorMessage(error));
      setFailureDetail(operationErrorDetail(error));
    } finally {
      setBusy(false);
    }
  }, [session, target, infrastructureId, loadDispatches]);

  return (
    <div className="yc-stack">
      <header className="yc-page-header">
        <div>
          <h1>Plans</h1>
          <p className="yc-muted">
            Construire une paire depuis une révision gelée, l’approuver dans la
            fenêtre native, et lire ce qui a été lancé
          </p>
        </div>
        <Button icon={RefreshCw} onClick={onRefresh}>
          Actualiser
        </Button>
      </header>

      {failure ? (
        <Banner icon={CircleHelp} title="Opération refusée" tone="danger">
          <p>{failure}</p>
          {/* Le contrôle qui a refusé, quand le cœur l’a nommé. Il est rendu à
              côté de la phrase et jamais à sa place : la phrase dit ce qu’un
              humain doit comprendre, celle-ci lui donne de quoi rapporter ce
              qu’il a vu quand la première ne suffit pas. */}
          {failureDetail ? <p className="yc-mono yc-muted">{failureDetail}</p> : null}
        </Banner>
      ) : null}

      <Card>
        <h3>Déployer une révision gelée</h3>
        <p className="yc-prose">
          Rien n’est assemblé à la main. Nommez la machine et la révision : le
          Controller construit la paire, et cette Console n’en montre que des
          phrases. Le compte, le foyer, les volumes, l’environnement et les noms
          de secrets viennent de la révision gelée, et d’aucun champ ci-dessous.
        </p>
        <div className="yc-plan-form">
          <Field id="yc-plan-machine" label="Machine">
            <TextInput
              id="yc-plan-machine"
              value={machineId}
              onChange={(event) => setMachineId(event.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field id="yc-plan-slug" label="Service défini">
            <select
              id="yc-plan-slug"
              className="yc-select"
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
            >
              <option value="">—</option>
              {frozen.map((entry) => (
                <option key={entry.definition_sha256} value={entry.slug}>
                  {entry.slug}
                </option>
              ))}
            </select>
          </Field>
          <Field id="yc-plan-image" label="Empreinte de l’image">
            <TextInput
              id="yc-plan-image"
              value={imageDigest}
              onChange={(event) => setImageDigest(event.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field id="yc-plan-port" label="Port local">
            <TextInput
              id="yc-plan-port"
              value={localPort}
              onChange={(event) => setLocalPort(event.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field id="yc-plan-origin" label="Nom public">
            <TextInput
              id="yc-plan-origin"
              value={originHost}
              onChange={(event) => setOriginHost(event.target.value)}
              autoComplete="off"
            />
          </Field>
        </div>
        <Button icon={ScrollText} onClick={readPair} disabled={busy || slug === ""}>
          Déployer
        </Button>
      </Card>

      {pair ? (
        <Card raised>
          <h3>Ce qui sera signé</h3>
          <p className="yc-prose">
            Ces phrases sont celles que la fenêtre native affichera. Elles ont
            été dérivées des deux documents que ce cœur a tenus contre leurs
            propres empreintes ; les deux dernières se terminent par ces
            empreintes.
          </p>
          <ul className="yc-plan-lines">
            {pair.confirmation_lines.map((line, index) => (
              <li key={`${index}-${line.slice(0, 24)}`}>{line}</li>
            ))}
          </ul>
          {session ? (
            <div className="yc-plan-session">
              {session.state === "open" ? (
                <>
                  <Badge tone="neutral">Fenêtre ouverte</Badge>
                  <p className="yc-prose">
                    Répondez dans la fenêtre séparée. Cette Console ne peut pas
                    répondre à votre place, et n’affiche pas ce qu’elle montre.
                  </p>
                  <Button icon={X} onClick={cancelConsent} intent="secondary">
                    Annuler la demande
                  </Button>
                </>
              ) : session.confirmed ? (
                <>
                  <Badge tone="success">Approuvé dans la fenêtre native</Badge>
                  <p className="yc-prose">
                    Rien n’est encore parti. Signer scelle ces deux empreintes
                    sous votre clé et remet l’approbation au Controller, qui
                    dépense la position de cette machine avant d’ouvrir quoi que
                    ce soit. C’est une autorité à un coup.
                  </p>
                  <Button
                    icon={ShieldCheck}
                    intent="primary"
                    loading={busy}
                    onClick={() => void submitDecision()}
                  >
                    Signer et lancer
                  </Button>
                </>
              ) : (
                <Badge tone="warning">Refusé — rien n’a été signé</Badge>
              )}
            </div>
          ) : (
            <Button icon={ShieldCheck} onClick={openConsent}>
              Lire et approuver dans la fenêtre native
            </Button>
          )}
        </Card>
      ) : null}

      <Card>
        <h3>Histoire des lancements</h3>
        {dispatches.length === 0 ? (
          <p className="yc-prose">
            Aucun plan n’a encore été lancé depuis cette Console.
          </p>
        ) : (
          <ul className="yc-dispatch-list">
            {dispatches.map((entry) => {
              const state = DISPATCH_STATES[entry.state];
              const reached = reachedStep(entry.state);
              return (
                <li key={entry.approval_sha256} className="yc-dispatch">
                  <div className="yc-dispatch-head">
                    <span className="yc-dispatch-machine">{entry.machine_id}</span>
                    <span className="yc-dispatch-operation">{entry.operation}</span>
                    <Badge tone={state.tone}>{state.label}</Badge>
                  </div>
                  <ol className="yc-journey">
                    {JOURNEY.map((step, index) => (
                      <li
                        key={step.key}
                        className={index <= reached ? "yc-journey-reached" : undefined}
                      >
                        {step.label}
                      </li>
                    ))}
                  </ol>
                  <p className="yc-prose">{state.sentence}</p>
                  <dl className="yc-dispatch-facts">
                    <dt>Position</dt>
                    <dd>{entry.sequence}</dd>
                    <dt>Approuvé le</dt>
                    <dd>{instant(entry.accepted_at_unix)}</dd>
                    <dt>Conclu le</dt>
                    <dd>{instant(entry.finished_at_unix)}</dd>
                    <dt>Empreinte du plan</dt>
                    <dd className="yc-digest">{entry.plan_sha256}</dd>
                  </dl>
                  {entry.state === "reported" ? (
                    <p className="yc-prose">
                      La machine a conclu {entry.reported_outcome || "sans nommer d’issue"}
                      {entry.reported_changed
                        ? ", et elle a changé quelque chose."
                        : ", et elle n’a rien changé."}
                    </p>
                  ) : null}
                  {/* La phrase de la machine est citée, jamais réécrite ; celle
                      du produit est distincte, pour qu’un lecteur sache
                      laquelle il lit. */}
                  {entry.machine_sentence ? (
                    <blockquote className="yc-machine-sentence">
                      {entry.machine_sentence}
                    </blockquote>
                  ) : null}
                  {entry.controller_observation ? (
                    <p className="yc-observation">{entry.controller_observation}</p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { CheckCircle2, ChevronRight, ServerCog } from "lucide-react";

import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import type {
  BootstrapActionName,
  BootstrapSessionView,
  BootstrapStartInput,
  LedgerItemView,
} from "./models";

/// Les mots français du déroulé. Le vocabulaire est clos des deux côtés :
/// une valeur inconnue ne peut pas arriver d'un protocole validé, et ces
/// tables sont totales par construction du type.
const LEDGER_KIND_WORDS: Record<LedgerItemView["kind"], string> = {
  package: "paquet",
  account: "compte",
  directory: "répertoire",
  file: "fichier",
  unit_state: "état d’unité",
  credential_source: "source de credentials",
  association: "association",
};
const LEDGER_PROVENANCE_WORDS: Record<LedgerItemView["provenance"], string> = {
  created: "posé par ce parcours",
  found: "déjà présent",
  unknown: "incertain — établi par personne",
};
import { operationErrorDetail, operationErrorMessage } from "./errors";
import { nativeConsole } from "./native";

/// « Créer une infrastructure », du premier champ au Controller actif.
///
/// Le parcours est une suite de consentements NATIFS : chaque étape lance une
/// session d'amorçage, la fenêtre de l'Assistant s'ouvre hors de cette WebView,
/// et cette vue ne fait que nommer — ce qui va être approuvé, puis l'issue que
/// la session a réellement rendue. Rien ne s'exécute ici : la vue ne tient ni
/// secret, ni commande, ni verdict, et un refus est toujours la phrase d'un
/// contrôle qui a parlé, jamais du JSON.
///
/// Un état partiel n'est jamais annoncé comme succès : chaque étape franchie
/// nomme ce qu'elle a rendu, et l'écran final nomme ce qui est fait — posé,
/// activé — et ce qui reste — l'association, qui est le parcours voisin.

/// Les trois étapes d'amorçage, dans l'ordre que le contrat fixe. Chacune est
/// une session : l'audit n'écrit rien, la pose laisse la machine inerte,
/// l'activation met la seule unité approuvée en écoute.
const BOOTSTRAP_STEPS: readonly {
  key: "audit" | "install" | "activate";
  action: BootstrapActionName | null;
  title: string;
  /// Ce que l'humain s'apprête à approuver — dit AVANT que la fenêtre s'ouvre.
  announce: string;
  /// Ce que l'issue vérifiée signifie — et seulement elle.
  achieved: string;
}[] = [
  {
    key: "audit",
    action: null,
    title: "Audit en lecture seule",
    announce:
      "La fenêtre de l’Assistant va s’ouvrir pour un audit en lecture seule : la machine est observée, rien n’y est écrit.",
    achieved: "La machine a été auditée en lecture seule. Rien n’a été écrit.",
  },
  {
    key: "install",
    action: "install_server_bundle",
    title: "Pose du lot serveur",
    announce:
      "La fenêtre de l’Assistant va s’ouvrir pour poser le lot vérifié. À la fin de cette étape, rien n’écoute encore.",
    achieved: "Le lot est posé et vérifié sur la machine. Rien n’écoute encore.",
  },
  {
    key: "activate",
    action: "activate_approved_controller",
    title: "Activation du Controller",
    announce:
      "La fenêtre de l’Assistant va s’ouvrir pour activer la seule unité approuvée du plan.",
    achieved: "Le Controller est actif sur la machine.",
  },
];

/// L'issue d'une session, dans les mots de la clôture d'affaires. Chaque
/// terminal du cycle de vie a sa phrase ; « en attente » n'en est pas une.
function outcomeSentence(lifecycle: BootstrapSessionView["lifecycle"]): string | null {
  switch (lifecycle) {
    case "awaiting_native_assistant":
      return null;
    case "access_verified":
      return null; // La phrase du succès appartient à l'étape, qui sait ce qu'il couvre.
    case "refused":
      return "L’Assistant a refusé : l’humain a décliné dans la fenêtre, ou un contrôle du produit a refusé l’état constaté. La machine reste dans l’état que le registre nomme.";
    case "cancelled":
      return "La session a été annulée avant sa fin. Rien de nouveau n’a été approuvé.";
    case "unavailable":
      return "L’Assistant n’a pas pu conclure cette session. Rien n’a été approuvé, et rien de partiel n’est annoncé comme un succès.";
  }
}

type StepOutcome = {
  key: (typeof BOOTSTRAP_STEPS)[number]["key"];
  sentence: string;
  /// Le déroulé de la séquence quand l'étape en a joué une : chaque entrée
  /// nomme ce qui a été rendu et d'où il vient. L'audit n'en porte pas.
  deroule: readonly LedgerItemView[] | null;
};

export function CreateInfrastructureView({
  onCancel,
  onAssociate,
}: {
  onCancel: () => void;
  onAssociate: () => void;
}) {
  // La déclaration de la cible : ce que l'humain DIT de sa machine, transporté
  // sans être jugé — les portes de l'Assistant confrontent, cette vue nomme.
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("");
  const [hostKey, setHostKey] = useState("");
  const [isPrivate, setIsPrivate] = useState(true);
  const [normallyOn, setNormallyOn] = useState(true);
  // Les trois adresses que l'unité du Controller lira. L'Assistant composera
  // le fichier et montrera son empreinte AVANT le consentement de la pose.
  const [listen, setListen] = useState("");
  const [allowedSource, setAllowedSource] = useState("");
  const [relayEndpoint, setRelayEndpoint] = useState("");

  const [stepIndex, setStepIndex] = useState<number | null>(null);
  const [done, setDone] = useState<StepOutcome[]>([]);
  const [awaiting, setAwaiting] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  // La seconde moitié d'un refus qui en a une : le contrôle qui a refusé l'a
  // nommée — pour l'entrée trop étroite, c'est ce que l'entrée permet
  // aujourd'hui, sans quoi l'humain devine au lieu de choisir entre ses deux
  // issues (constat n°10 du contrat).
  const [failureDetail, setFailureDetail] = useState<string | null>(null);
  // Le déroulé du registre au moment où l'étape s'est arrêtée : ce qui a été
  // rendu, entrée par entrée. Un état partiel se NOMME — il ne se devine pas,
  // et il ne se cache pas derrière une phrase qui renverrait à un registre
  // que personne ne peut lire (constats n°6 et n°7 du contrat).
  const [deroule, setDeroule] = useState<readonly LedgerItemView[] | null>(null);
  const pollTimer = useRef<number | null>(null);
  const activeRequest = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      if (pollTimer.current !== null) {
        window.clearInterval(pollTimer.current);
      }
    };
  }, []);

  function declaredInput(action: BootstrapActionName | null): BootstrapStartInput {
    const input: BootstrapStartInput = {
      mode: "create",
      target: {
        host: host.trim(),
        port: Number.parseInt(port, 10),
        username: username.trim(),
        host_key_sha256: hostKey.trim(),
        access_kind: "administrator",
      },
    };
    if (action !== null) {
      input.action = action;
      input.declared_target = { private: isPrivate, normally_on: normallyOn };
    }
    if (action === "install_server_bundle") {
      input.machine_configuration = {
        listen: listen.trim(),
        allowed_source: allowedSource.trim(),
        relay_endpoint: relayEndpoint.trim(),
      };
    }
    return input;
  }

  /// Une étape : démarrer la session, puis relire son issue jusqu'au terminal.
  /// La fenêtre vit hors de cette vue ; ici, seule l'issue est nommée.
  async function runStep(index: number) {
    const step = BOOTSTRAP_STEPS[index];
    if (step === undefined) {
      return;
    }
    setStepIndex(index);
    setFailure(null);
    setFailureDetail(null);
    setDeroule(null);
    setAwaiting(step.announce);
    let session: BootstrapSessionView;
    try {
      session = await nativeConsole.startBootstrap(declaredInput(step.action));
    } catch (error: unknown) {
      setAwaiting(null);
      setFailure(operationErrorMessage(error));
      setFailureDetail(operationErrorDetail(error));
      return;
    }
    const requestId = session.request_id;
    activeRequest.current = requestId;
    pollTimer.current = window.setInterval(() => {
      void (async () => {
        let read: BootstrapSessionView;
        try {
          read = await nativeConsole.bootstrapStatus(requestId);
        } catch (error: unknown) {
          stopPolling();
          setAwaiting(null);
          setFailure(operationErrorMessage(error));
          setFailureDetail(operationErrorDetail(error));
          return;
        }
        if (read.lifecycle === "awaiting_native_assistant") {
          return;
        }
        stopPolling();
        setAwaiting(null);
        if (read.lifecycle === "access_verified") {
          setDone((current) => [
            ...current,
            { key: step.key, sentence: step.achieved, deroule: read.install_ledger ?? null },
          ]);
          setStepIndex(null);
        } else {
          setFailure(outcomeSentence(read.lifecycle));
          setDeroule(read.install_ledger ?? null);
        }
      })();
    }, 1000);
  }

  function stopPolling() {
    if (pollTimer.current !== null) {
      window.clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }

  /// Abandonner pendant qu'une session court : la fenêtre de l'Assistant est
  /// annulée AVANT de quitter la vue — un parcours qu'on quitte ne laisse pas
  /// une fenêtre orpheline attendre un consentement que personne ne lira.
  async function abandon() {
    const requestId = activeRequest.current;
    if (requestId !== null && awaiting !== null) {
      stopPolling();
      try {
        await nativeConsole.cancelBootstrap(requestId);
      } catch {
        // La session a pu se conclure entre le clic et l'annulation : l'issue
        // appartient alors à la clôture, et quitter reste licite.
      }
    }
    onCancel();
  }

  const declarationComplete =
    host.trim() !== "" &&
    username.trim() !== "" &&
    hostKey.trim() !== "" &&
    Number.isInteger(Number.parseInt(port, 10)) &&
    listen.trim() !== "" &&
    allowedSource.trim() !== "" &&
    relayEndpoint.trim() !== "";
  const nextIndex = done.length;
  const finished = nextIndex >= BOOTSTRAP_STEPS.length;
  const running = stepIndex !== null && awaiting !== null;

  return (
    <div className="yc-stack">
      <header className="yc-page-header">
        <div>
          <h1>Créer une infrastructure</h1>
          <p className="yc-muted">
            Trois consentements dans la fenêtre de l’Assistant : auditer, poser, activer. Chaque
            étape nomme son issue avant que la suivante s’ouvre.
          </p>
        </div>
      </header>

      <Card>
        <h2>La machine, telle que vous la déclarez</h2>
        <p className="yc-muted">
          Ce que vous déclarez ici est confronté par l’Assistant à ce que la machine répond —
          jamais cru sur parole.
        </p>
        <div className="yc-form-grid">
          <Field id="ci-host" label="Nom de la machine" help="Le nom que la session résoudra une seule fois.">
            <TextInput id="ci-host" value={host} onChange={(event) => setHost(event.target.value)} disabled={finished || running} />
          </Field>
          <Field id="ci-port" label="Port SSH">
            <TextInput id="ci-port" value={port} onChange={(event) => setPort(event.target.value)} disabled={finished || running} />
          </Field>
          <Field id="ci-username" label="Compte prêté" help="Le compte administrateur dont l’accès est prêté, le temps du parcours.">
            <TextInput id="ci-username" value={username} onChange={(event) => setUsername(event.target.value)} disabled={finished || running} />
          </Field>
          <Field id="ci-hostkey" label="Empreinte de la clé d’hôte" help="SHA256:… — confirmée hors bande, jamais apprise à la première réponse.">
            <TextInput id="ci-hostkey" value={hostKey} onChange={(event) => setHostKey(event.target.value)} disabled={finished || running} />
          </Field>
        </div>
        <div className="yc-cluster">
          <label className="yc-checkbox">
            <input
              type="checkbox"
              checked={isPrivate}
              onChange={(event) => setIsPrivate(event.target.checked)}
              disabled={finished || running}
            />
            Cette machine n’est pas exposée publiquement
          </label>
          <label className="yc-checkbox">
            <input
              type="checkbox"
              checked={normallyOn}
              onChange={(event) => setNormallyOn(event.target.checked)}
              disabled={finished || running}
            />
            Elle est normalement allumée
          </label>
        </div>
      </Card>

      <Card>
        <h2>Ce que le Controller écoutera</h2>
        <p className="yc-muted">
          L’Assistant composera la configuration depuis ces trois adresses et montrera son
          empreinte dans la fenêtre de pose, avant votre consentement.
        </p>
        <div className="yc-form-grid">
          <Field id="ci-listen" label="Adresse d’écoute" help="Exemple : 192.168.1.10:9443">
            <TextInput id="ci-listen" value={listen} onChange={(event) => setListen(event.target.value)} disabled={finished || running} />
          </Field>
          <Field id="ci-allowed" label="Source autorisée" help="Exemple : 192.168.1.0/24">
            <TextInput id="ci-allowed" value={allowedSource} onChange={(event) => setAllowedSource(event.target.value)} disabled={finished || running} />
          </Field>
          <Field id="ci-relay" label="Point de rendez-vous du Relay" help="Exemple : 192.168.1.9:9444">
            <TextInput id="ci-relay" value={relayEndpoint} onChange={(event) => setRelayEndpoint(event.target.value)} disabled={finished || running} />
          </Field>
        </div>
      </Card>

      <Card>
        <h2>Les trois consentements</h2>
        <ol className="yc-step-list">
          {BOOTSTRAP_STEPS.map((step, index) => {
            const outcome = done.find((entry) => entry.key === step.key);
            return (
              <li key={step.key} className="yc-step">
                <div className="yc-cluster">
                  {outcome ? (
                    <Badge tone="success" icon={CheckCircle2}>
                      {step.title}
                    </Badge>
                  ) : (
                    <Badge tone={index === nextIndex ? "accent" : "neutral"}>{step.title}</Badge>
                  )}
                </div>
                {outcome ? <p>{outcome.sentence}</p> : null}
                {/* Ce que la séquence de cette étape a rendu, entrée par
                    entrée — la moitié visible de « tout effet naît d'un plan
                    approuvé et visible ». */}
                {outcome && outcome.deroule && outcome.deroule.length > 0 ? (
                  <ul className="yc-mono yc-muted">
                    {outcome.deroule.map((item) => (
                      <li key={`${item.kind}:${item.name}`}>
                        {LEDGER_KIND_WORDS[item.kind]} {item.name} — {LEDGER_PROVENANCE_WORDS[item.provenance]}
                      </li>
                    ))}
                  </ul>
                ) : null}
                {index === nextIndex && !finished ? (
                  <Button
                    intent="primary"
                    icon={ChevronRight}
                    onClick={() => void runStep(index)}
                    disabled={!declarationComplete || running}
                  >
                    {index === 0 ? "Commencer par l’audit" : `Continuer : ${step.title.toLowerCase()}`}
                  </Button>
                ) : null}
              </li>
            );
          })}
        </ol>
        {awaiting ? (
          <Banner icon={ServerCog} title="Fenêtre de l’Assistant ouverte">
            {awaiting}
          </Banner>
        ) : null}
        {failure ? (
          <Banner tone="danger" icon={ServerCog} title="Cette étape n’a pas abouti">
            {failure}
            {/* La seconde moitié du refus, quand le contrôle l'a nommée : la
                phrase dit ce qu'un humain doit comprendre, celle-ci lui donne
                l'existant à lire — pour l'entrée trop étroite, ce que
                l'entrée sudoers permet aujourd'hui. */}
            {failureDetail ? <p className="yc-mono yc-muted">{failureDetail}</p> : null}
            {/* Le déroulé : ce que la séquence avait rendu quand elle s'est
                arrêtée, entrée par entrée. La machine reste dans l'état que ce
                registre nomme — et le voici, au lieu d'une allusion. */}
            {deroule && deroule.length > 0 ? (
              <ul className="yc-mono yc-muted">
                {deroule.map((item) => (
                  <li key={`${item.kind}:${item.name}`}>
                    {LEDGER_KIND_WORDS[item.kind]} {item.name} — {LEDGER_PROVENANCE_WORDS[item.provenance]}
                  </li>
                ))}
              </ul>
            ) : null}
          </Banner>
        ) : null}
      </Card>

      {finished ? (
        <Card raised>
          <div className="yc-cluster">
            <CheckCircle2 className="yc-icon" aria-hidden="true" />
            <h2>Le Controller est actif</h2>
          </div>
          <p>
            La machine a été auditée, le lot posé, le Controller activé. Il reste une chose, et
            une seule : associer cette Console à ce Controller — c’est le parcours « Associer »,
            avec la fenêtre locale du Controller.
          </p>
        </Card>
      ) : null}

      <div className="yc-cluster">
        {finished ? (
          <Button intent="primary" onClick={onAssociate}>
            Associer cette Console
          </Button>
        ) : null}
        <Button onClick={() => void abandon()}>
          {finished ? "Revenir aux infrastructures" : "Abandonner ce parcours"}
        </Button>
      </div>
    </div>
  );
}

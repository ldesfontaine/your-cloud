import {
  ClipboardPaste,
  FileCheck2,
  GitCompareArrows,
  Info,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  Snowflake,
} from "lucide-react";
import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { Badge, Banner, Button, Card, Field, TextInput } from "../design/primitives";
import { operationErrorMessage } from "./errors";
import type {
  FrozenDefinitionView,
  PasteNote,
  PasteNoteName,
  ServiceDefinitionDraft,
  ServiceDefinitionFieldName,
  ServiceDefinitionFieldRefusal,
  ServiceDefinitionRefusalName,
  ServiceDefinitionReview,
  ServiceDefinitionsProjection,
} from "./models";
import { nativeConsole } from "./native";

// Le contrat d’éligibilité, en phrases et jamais en options. Il est affiché
// dans cette vue avant tout gel, parce qu’une image qui ne tient pas ces
// phrases n’est pas condamnée : elle attend un contrat futur, ou reste un
// élément externe que le produit représente sans le posséder. Rien ici n’est
// une case à cocher : ce sont des constats que l’utilisateur fait sur sa propre
// image, et le produit ne peut pas les faire à sa place.
const ELIGIBILITY_CONTRACT: readonly string[] = [
  "Elle court rootless, sous un compte ordinaire, sans capacité ni privilège.",
  "Elle écoute sur un seul port, celui que la définition déclare.",
  "Elle écrit ses données durables uniquement sous les chemins déclarés en volumes, et ses brouillons sous les chemins déclarés en tmpfs.",
  "Elle sert sous lecture seule : tout le reste de son système de fichiers est figé, et une image qui refuse de démarrer ainsi échoue de façon contrôlée.",
  "Elle ne sort pas sur le réseau : pas de téléchargement au démarrage, pas de télémétrie, pas de relais — ce qui tourne est ce que l’image contient.",
  "Elle se configure par lignes d’environnement inertes et reçoit ses secrets par clés générées sur la machine, jamais par des valeurs transportées.",
  "Elle est joignable par empreinte depuis la machine : un tag n’est une identité nulle part dans ce produit.",
];

// Les champs d’une définition, dans l’ordre du contrat. La même liste sert le
// formulaire et le diff, pour qu’un champ ajouté au document ne puisse pas être
// affiché d’un côté et manquant de l’autre.
const DEFINITION_FIELDS: ReadonlyArray<{
  field: Exclude<ServiceDefinitionFieldName, "schema_version" | "slug" | "document">;
  label: string;
}> = [
  { field: "image_repository", label: "Dépôt d’image" },
  { field: "container_port", label: "Port conteneur" },
  { field: "volumes", label: "Volumes" },
  { field: "tmpfs", label: "Brouillons en mémoire" },
  { field: "environment", label: "Lignes d’environnement" },
  { field: "secret_keys", label: "Clés de secrets" },
];

const EMPTY_DRAFT: ServiceDefinitionDraft = {
  slug: "",
  image_repository: "",
  container_port: 0,
  volumes: [],
  tmpfs: [],
  environment: [],
  secret_keys: [],
};

export function ServicesView({
  definitions,
  loading,
  onRefresh,
  onFroze,
  infrastructureId,
}: {
  definitions: ServiceDefinitionsProjection | null;
  loading: boolean;
  onRefresh: () => void;
  onFroze: () => void;
  infrastructureId: string;
}) {
  const [draft, setDraft] = useState<ServiceDefinitionDraft>(EMPTY_DRAFT);
  const [review, setReview] = useState<ServiceDefinitionReview | null>(null);
  // Deux étapes, et le gel n’existe que dans la seconde : le panneau des
  // conséquences n’est pas un écran que la vue peut choisir de sauter, c’est le
  // seul endroit d’où part une soumission.
  const [stage, setStage] = useState<"form" | "consequences">("form");
  const [pasted, setPasted] = useState("");
  const [notes, setNotes] = useState<PasteNote[]>([]);
  const [failure, setFailure] = useState<string | null>(null);
  const [freezing, setFreezing] = useState(false);
  const reviewGeneration = useRef(0);

  // La relecture est demandée au miroir à chaque frappe, et jamais calculée
  // ici : c’est la grammaire du Controller, ou ce n’en est pas une.
  useEffect(() => {
    const generation = reviewGeneration.current + 1;
    reviewGeneration.current = generation;
    nativeConsole
      .reviewServiceDefinition(draft)
      .then((next) => {
        if (generation === reviewGeneration.current) setReview(next);
      })
      .catch((error: unknown) => {
        if (generation === reviewGeneration.current) {
          setReview(null);
          setFailure(operationErrorMessage(error));
        }
      });
  }, [draft]);

  const prefill = useCallback(async () => {
    setFailure(null);
    try {
      const paste = await nativeConsole.parseServiceDefinitionPaste(pasted);
      setNotes(paste.notes);
      // Un collage préremplit et rien d’autre : on revient toujours au
      // formulaire, jamais au panneau, et rien n’est soumis.
      setStage("form");
      if (paste.source !== "unrecognised") setDraft(paste.draft);
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    }
  }, [pasted]);

  const freeze = useCallback(async () => {
    if (review?.state !== "ready") return;
    setFreezing(true);
    setFailure(null);
    try {
      await nativeConsole.freezeServiceDefinition(
        infrastructureId,
        review.definition_document,
        review.definition_sha256,
      );
      setStage("form");
      onFroze();
    } catch (error: unknown) {
      setFailure(operationErrorMessage(error));
    } finally {
      setFreezing(false);
    }
  }, [infrastructureId, onFroze, review]);

  // Un formulaire que personne n’a touché ne refuse rien. Le miroir le refuse —
  // un slug vide n’est pas un slug — mais reprocher à un humain de n’avoir pas
  // encore écrit serait rendre un refus qui ne nomme aucune erreur. Les phrases
  // arrivent dès la première frappe, et le bouton qui mène au panneau reste
  // inerte jusque-là.
  const pristine = draft === EMPTY_DRAFT;
  const refusals = !pristine && review?.state === "refused" ? review.refusals : [];
  return (
    <div className="yc-stack">
      <header className="yc-page-header">
        <div>
          <h1>Services</h1>
          <p className="yc-muted">
            Les définitions que vous avez écrites, leurs révisions gelées et ce qu’elles décident
          </p>
        </div>
        <Button icon={RefreshCw} loading={loading} onClick={onRefresh}>
          Actualiser
        </Button>
      </header>
      {failure ? (
        <Banner icon={ShieldAlert} title="Opération refusée" tone="danger">
          <p>{failure}</p>
        </Banner>
      ) : null}
      <EligibilityContract />
      {/* Le panneau n’existe que pour un brouillon que le miroir accepte, et la
          seconde condition n’est pas une précaution de style : si la relecture
          cessait de rendre « prêt », une vue qui n’afficherait que le panneau
          laisserait un humain devant un écran vide. Le repli est le formulaire,
          d’où l’on peut toujours repartir. */}
      {stage === "form" || review?.state !== "ready" ? (
        <>
          <PasteCard
            pasted={pasted}
            notes={notes}
            onChange={(next) => setPasted(next)}
            onPrefill={() => void prefill()}
          />
          <DefinitionForm
            draft={draft}
            refusals={refusals}
            onChange={setDraft}
            onReview={() => setStage("consequences")}
            reviewable={review?.state === "ready"}
          />
        </>
      ) : (
        <ConsequencesPanel
          review={review}
          freezing={freezing}
          onBack={() => setStage("form")}
          onFreeze={() => void freeze()}
        />
      )}
      <FrozenDefinitions definitions={definitions} />
    </div>
  );
}

function EligibilityContract() {
  return (
    <Banner icon={ScrollText} title="Ce qu’une image doit accepter" tone="accent">
      <p>
        Ce moteur ne fournit aucun catalogue et ne recommande aucune application. Une image est
        éligible si elle tient les phrases suivantes, et c’est un constat que vous faites sur votre
        propre image avant de geler quoi que ce soit.
      </p>
      <ul className="yc-sentence-list">
        {ELIGIBILITY_CONTRACT.map((sentence) => (
          <li key={sentence}>{sentence}</li>
        ))}
      </ul>
      <p>
        Une application qui ne tient pas ces phrases n’est pas condamnée : elle attend un contrat
        futur qui nommera l’élargissement, ou reste un élément externe que le produit représente
        sans le posséder.
      </p>
    </Banner>
  );
}

function PasteCard({
  pasted,
  notes,
  onChange,
  onPrefill,
}: {
  pasted: string;
  notes: PasteNote[];
  onChange: (value: string) => void;
  onPrefill: () => void;
}) {
  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2>Préremplir depuis un collage</h2>
          <p className="yc-muted">
            Un collage ne peut que préremplir. Rien n’est exécuté, rien ne part sur le réseau, rien
            n’est gelé ni soumis : le formulaire s’ouvre avec ce qui a pu être lu, et vous le
            relisez.
          </p>
        </div>
        <Field
          id="service-paste"
          label="Commande de conteneur ou document compose"
          help="Une commande docker run, ou un docker-compose.yml. Un document à plusieurs services ne préremplit que depuis un seul, et le dit."
        >
          <textarea
            id="service-paste"
            className="yc-input yc-textarea yc-mono"
            value={pasted}
            onChange={(event) => onChange(event.target.value)}
            spellCheck={false}
          />
        </Field>
        <div className="yc-cluster">
          <Button icon={ClipboardPaste} onClick={onPrefill}>
            Préremplir le formulaire
          </Button>
        </div>
        {notes.length > 0 ? (
          <dl className="yc-definition-list">
            {notes.map((note) => (
              <Fragment key={note.note}>
                <dt>{pasteNoteTitle(note.note)}</dt>
                <dd>
                  {pasteNoteSentence(note.note)}
                  {note.subjects.length > 0 ? (
                    <div className="yc-mono yc-paste__subjects" dir="ltr">
                      {note.subjects.join(" · ")}
                    </div>
                  ) : null}
                </dd>
              </Fragment>
            ))}
          </dl>
        ) : null}
      </div>
    </Card>
  );
}

function DefinitionForm({
  draft,
  refusals,
  onChange,
  onReview,
  reviewable,
}: {
  draft: ServiceDefinitionDraft;
  refusals: ServiceDefinitionFieldRefusal[];
  onChange: (draft: ServiceDefinitionDraft) => void;
  onReview: () => void;
  reviewable: boolean;
}) {
  const errorOf = (field: ServiceDefinitionFieldName) => refusalSentence(refusals, field);
  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2>Rédiger une définition</h2>
          <p className="yc-muted">
            Vous n’écrivez aucun YAML et vous ne nommez rien de ce que la machine possède : le
            compte, le foyer, les chemins hôte, les valeurs de secrets et la table de sortie
            dérivent du nom du service et d’aucun champ de ce formulaire.
          </p>
        </div>
        <div className="yc-form-grid">
          <Field
            id="definition-slug"
            label="Nom du service"
            help="16 caractères au plus. Tout le reste en dérive, à commencer par le compte de la machine."
            error={errorOf("slug")}
          >
            <TextInput
              id="definition-slug"
              className="yc-input yc-mono"
              value={draft.slug}
              maxLength={64}
              invalid={Boolean(errorOf("slug"))}
              spellCheck={false}
              onChange={(event) => onChange({ ...draft, slug: event.target.value })}
            />
          </Field>
          <Field
            id="definition-repository"
            label="Dépôt d’image"
            help="D’où les images de ce service viennent, jamais laquelle : ni tag, ni empreinte."
            error={errorOf("image_repository")}
          >
            <TextInput
              id="definition-repository"
              className="yc-input yc-mono"
              value={draft.image_repository}
              maxLength={255}
              invalid={Boolean(errorOf("image_repository"))}
              spellCheck={false}
              onChange={(event) => onChange({ ...draft, image_repository: event.target.value })}
            />
          </Field>
          <Field
            id="definition-port"
            label="Port conteneur"
            help="Le port que l’image écoute dans son propre espace de noms."
            error={errorOf("container_port")}
          >
            <TextInput
              id="definition-port"
              className="yc-input yc-mono"
              inputMode="numeric"
              value={draft.container_port === 0 ? "" : String(draft.container_port)}
              maxLength={5}
              invalid={Boolean(errorOf("container_port"))}
              onChange={(event) =>
                onChange({
                  ...draft,
                  container_port: Number.parseInt(event.target.value, 10) || 0,
                })
              }
            />
          </Field>
        </div>
        <ListField
          id="definition-volumes"
          label="Volumes"
          help="Un chemin conteneur par ligne. Ce qui doit survivre au conteneur ; la machine décide où cela vit."
          entries={draft.volumes}
          error={errorOf("volumes")}
          onChange={(volumes) => onChange({ ...draft, volumes })}
        />
        <ListField
          id="definition-tmpfs"
          label="Brouillons en mémoire"
          help="Un chemin conteneur par ligne. Ce que l’image exige d’écrire sous lecture seule, perdu à chaque arrêt."
          entries={draft.tmpfs}
          error={errorOf("tmpfs")}
          onChange={(tmpfs) => onChange({ ...draft, tmpfs })}
        />
        <ListField
          id="definition-environment"
          label="Lignes d’environnement"
          help="Une ligne CLÉ=valeur par ligne. Une valeur est affichée partout où la définition l’est : aucun secret n’y a sa place."
          entries={draft.environment}
          error={errorOf("environment")}
          preserveSpacing
          onChange={(environment) => onChange({ ...draft, environment })}
        />
        <ListField
          id="definition-secret-keys"
          label="Clés de secrets"
          help="Un nom par ligne. La machine générera une valeur par clé ; aucune valeur n’entre jamais dans un document de ce produit."
          entries={draft.secret_keys}
          error={errorOf("secret_keys")}
          onChange={(secret_keys) => onChange({ ...draft, secret_keys })}
        />
        {errorOf("document") ? (
          <Banner icon={ShieldAlert} title="Document trop large" tone="warning">
            <p>{errorOf("document")}</p>
          </Banner>
        ) : null}
        <div className="yc-cluster">
          <Button
            intent="primary"
            icon={FileCheck2}
            disabled={!reviewable}
            onClick={onReview}
          >
            Voir ce que la machine recevra
          </Button>
        </div>
      </div>
    </Card>
  );
}

// Les listes se saisissent une entrée par ligne. Les espaces sont retirés
// partout où ils ne peuvent rien vouloir dire — un chemin, une clé — et
// conservés dans une ligne d'environnement, où une valeur a le droit d'en
// porter : rogner une valeur serait modifier le document sans le dire.
function ListField({
  id,
  label,
  help,
  entries,
  error,
  preserveSpacing = false,
  onChange,
}: {
  id: string;
  label: string;
  help: string;
  entries: string[];
  error: string;
  preserveSpacing?: boolean;
  onChange: (entries: string[]) => void;
}) {
  return (
    <Field id={id} label={label} help={help} error={error}>
      <textarea
        id={id}
        className="yc-input yc-textarea yc-mono"
        value={entries.join("\n")}
        aria-invalid={Boolean(error)}
        spellCheck={false}
        onChange={(event) =>
          onChange(
            event.target.value
              .split("\n")
              .map((entry) => (preserveSpacing ? entry.replace(/\r$/u, "") : entry.trim()))
              .filter((entry) => entry.length > 0),
          )
        }
      />
    </Field>
  );
}

function ConsequencesPanel({
  review,
  freezing,
  onBack,
  onFreeze,
}: {
  review: Extract<ServiceDefinitionReview, { state: "ready" }>;
  freezing: boolean;
  onBack: () => void;
  onFreeze: () => void;
}) {
  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2>Ce que la machine recevra</h2>
          <p className="yc-muted">
            Geler ces octets ne crée rien et ne contacte aucune machine. Ce qui suit est ce qu’un
            plan de déploiement approuvé posera plus tard, et rien de tout cela n’est un champ que
            vous avez rempli.
          </p>
        </div>
        <ul className="yc-sentence-list">
          {review.confirmation_lines.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        {/* Les octets exacts, affichés entiers. La borne de 8192 octets existe
            en partie pour cela : la Console montre toujours le document entier,
            et jamais un résumé de ce qui sera gelé. */}
        <div>
          <h3>Document canonique gelé</h3>
          <pre className="yc-document" dir="ltr">
            {review.definition_document}
          </pre>
        </div>
        <div className="yc-cluster">
          <Button intent="primary" icon={Snowflake} loading={freezing} onClick={onFreeze}>
            Geler cette révision
          </Button>
          <Button onClick={onBack}>Revenir au formulaire</Button>
        </div>
      </div>
    </Card>
  );
}

function FrozenDefinitions({
  definitions,
}: {
  definitions: ServiceDefinitionsProjection | null;
}) {
  const entries = definitions?.definitions ?? [];
  if (entries.length === 0) {
    return (
      <Card>
        <h2>Aucune définition gelée</h2>
        <p>
          Rien n’a encore été gelé sur cette infrastructure. Une définition gelée ne crée aucune
          ressource : elle attend qu’un plan approuvé l’épingle par son empreinte.
        </p>
      </Card>
    );
  }
  // Les révisions se regroupent sous leur nom, dans l'ordre où le Controller
  // les a gelées : une révision est un nouveau gel qui coexiste avec toutes les
  // précédentes, et rien ne remplace jamais rien.
  const bySlug = new Map<string, FrozenDefinitionView[]>();
  for (const entry of entries) {
    bySlug.set(entry.slug, [...(bySlug.get(entry.slug) ?? []), entry]);
  }
  return (
    <div className="yc-definition-grid">
      {[...bySlug.entries()].map(([slug, revisions]) => (
        <DefinitionCard key={slug} slug={slug} revisions={revisions} />
      ))}
    </div>
  );
}

function DefinitionCard({ slug, revisions }: { slug: string; revisions: FrozenDefinitionView[] }) {
  const [compared, setCompared] = useState<string | null>(null);
  const latest = revisions.at(-1);
  const earlier = revisions.find((revision) => revision.definition_sha256 === compared) ?? null;
  if (!latest) return null;
  return (
    <Card>
      <div className="yc-stack">
        <div>
          <h2 className="yc-definition__slug" dir="ltr">
            {slug}
          </h2>
          <div className="yc-mono yc-definition__origin" dir="ltr">
            {latest.document.image_repository} · port {latest.document.container_port}
          </div>
        </div>
        <div className="yc-cluster">
          <Badge tone="success" icon={Snowflake}>
            Gelée
          </Badge>
          <Badge icon={Info}>
            {revisions.length} révision{revisions.length > 1 ? "s" : ""}
          </Badge>
        </div>
        {/* L'état « déployée » n'est pas affiché parce que rien ne le projette :
            aucune route de ce produit ne dit encore quelle machine exécute
            quelle révision. Nommer l'absence vaut mieux que rendre un état que
            la Console devrait deviner. */}
        <Banner icon={Info} title="Instances" tone="accent">
          <p>
            Aucune instance n’est affichée : ce palier ne projette pas encore quelle machine
            exécute quelle révision. Une définition gelée n’a par elle-même aucune instance, et
            déployer reste un plan approuvé à part.
          </p>
        </Banner>
        <dl className="yc-definition-list">
          <dt>Révision courante</dt>
          <dd className="yc-mono">{latest.definition_sha256}</dd>
          <dt>Gelée le</dt>
          <dd className="yc-mono">{latest.frozen_at}</dd>
          <dt>Origine</dt>
          <dd>
            {latest.interpolates_origin_host
              ? "Une ligne au moins consomme l’origine : un déploiement devra approuver un nom."
              : "Aucune ligne ne consomme d’origine : un plan qui en porterait une serait refusé."}
          </dd>
        </dl>
        {revisions.length > 1 ? (
          <div className="yc-stack">
            <Field
              id={`compare-${slug}`}
              label="Comparer la révision courante à"
              help="Un diff champ à champ entre deux gels. Les deux révisions restent lisibles : geler ne remplace jamais."
            >
              <select
                id={`compare-${slug}`}
                className="yc-select yc-mono"
                value={compared ?? ""}
                onChange={(event) => setCompared(event.target.value || null)}
              >
                <option value="">Aucune</option>
                {revisions
                  .filter((revision) => revision.definition_sha256 !== latest.definition_sha256)
                  .map((revision) => (
                    <option key={revision.definition_sha256} value={revision.definition_sha256}>
                      {revision.frozen_at}
                    </option>
                  ))}
              </select>
            </Field>
            {earlier ? <RevisionDiff earlier={earlier} later={latest} /> : null}
          </div>
        ) : null}
      </div>
    </Card>
  );
}

function RevisionDiff({
  earlier,
  later,
}: {
  earlier: FrozenDefinitionView;
  later: FrozenDefinitionView;
}) {
  return (
    <div className="yc-stack">
      <div className="yc-cluster">
        <GitCompareArrows className="yc-icon" aria-hidden="true" />
        <span className="yc-muted">Champ à champ, dans l’ordre du document</span>
      </div>
      <dl className="yc-definition-list">
        {DEFINITION_FIELDS.map(({ field, label }) => {
          const before = fieldLines(earlier, field);
          const after = fieldLines(later, field);
          const unchanged = before.join("\n") === after.join("\n");
          return (
            <Fragment key={field}>
              <dt>{label}</dt>
              <dd>
                {unchanged ? (
                  <span className="yc-muted">Inchangé</span>
                ) : (
                  <div className="yc-diff">
                    <div className="yc-mono yc-diff__side" dir="ltr">
                      {before.length === 0 ? "—" : before.join("\n")}
                    </div>
                    <div className="yc-mono yc-diff__side" dir="ltr">
                      {after.length === 0 ? "—" : after.join("\n")}
                    </div>
                  </div>
                )}
              </dd>
            </Fragment>
          );
        })}
      </dl>
    </div>
  );
}

function fieldLines(
  revision: FrozenDefinitionView,
  field: (typeof DEFINITION_FIELDS)[number]["field"],
): string[] {
  const document = revision.document;
  switch (field) {
    case "image_repository":
      return [document.image_repository];
    case "container_port":
      return [String(document.container_port)];
    case "volumes":
      return document.volumes;
    case "tmpfs":
      return document.tmpfs;
    case "environment":
      return document.environment;
    case "secret_keys":
      return document.secret_keys;
  }
}

// Le premier refus d'un champ, en une phrase. Chaque nom de la liste fermée a
// la sienne : la Console ne rend jamais un code au visage d'un humain, et un nom
// sans phrase est un trou que le contrat de source rougit.
function refusalSentence(
  refusals: ServiceDefinitionFieldRefusal[],
  field: ServiceDefinitionFieldName,
): string {
  const refusal = refusals.find((candidate) => candidate.field === field);
  if (!refusal) return "";
  const sentence = refusalName(refusal.refusal);
  return refusal.entry === null ? sentence : `Entrée ${refusal.entry + 1} — ${sentence}`;
}

function refusalName(name: ServiceDefinitionRefusalName): string {
  switch (name) {
    case "unknown_schema_version":
      return "Ce document annonce une version que ce palier ne lit pas.";
    case "slug_grammar":
      return "Un nom de service tient en 16 caractères au plus : minuscules, chiffres et tirets, ouvrant sur une lettre ou un chiffre. Le compte dérivé doit tenir dans les 32 caractères d’un nom d’utilisateur, et la dérivation ne tronque jamais.";
    case "slug_reserved":
      return "Ce nom appartient déjà au produit. Quatre noms sont réservés — bentopdf, vaultwarden, probe, entrypoint — pour qu’un nom désigne toujours exactement une porte.";
    case "image_repository_pinned":
      return "Une définition dit d’où les images viennent, jamais laquelle : retirez le tag ou l’empreinte. L’empreinte de l’instance vit dans le plan qui la déploie.";
    case "image_repository_grammar":
      return "Un dépôt s’écrit registre puis chemin, en minuscules. Un premier composant sans point ni port serait résolu par une liste de recherche, c’est-à-dire par une seconde vérité à côté de l’empreinte.";
    case "container_port_range":
      return "Le port que l’image écoute dans son propre espace de noms va de 1 à 65535.";
    case "list_too_long":
      return "Cette liste dépasse sa borne : 8 volumes, 8 brouillons en mémoire, 32 lignes d’environnement, 16 clés de secrets.";
    case "container_path_grammar":
      return "Un chemin conteneur est absolu et normalisé : aucun segment « . » ou « .. », aucune barre double, aucune barre finale, jamais « / » seul, et des segments en minuscules, chiffres, point, tiret bas et tiret.";
    case "mounts_overlap":
      return "Deux montures qui se recouvrent seraient deux écritures dont l’ordre déciderait, et l’ordre n’est pas un champ. Aucune entrée ne peut être une autre ni l’ouvrir segment par segment.";
    case "environment_line_shape":
      return "Une ligne d’environnement s’écrit CLÉ=valeur.";
    case "key_grammar":
      return "Une clé s’écrit en majuscules, chiffres et tirets bas, ouvre sur une majuscule et tient en 64 caractères.";
    case "value_grammar":
      return "Une valeur est de l’ASCII imprimable borné à 512 octets, où une accolade n’apparaît que dans la seule séquence que ce produit interpole.";
    case "key_already_declared":
      return "Ce nom est déjà pris : une clé est un nom dans un seul espace de noms, et les lignes d’environnement et les clés de secrets le partagent.";
    case "document_too_large":
      return "Chaque champ tient sa borne et le document dépasse la sienne, qui est de 8192 octets.";
  }
}

function pasteNoteTitle(name: PasteNoteName): string {
  switch (name) {
    case "nothing_recognised":
      return "Rien de reconnu";
    case "paste_too_large":
      return "Collage trop grand";
    case "single_service_only":
      return "Un seul service";
    case "image_pin_dropped":
      return "Tag ou empreinte écarté";
    case "host_side_dropped":
      return "Côté hôte écarté";
    case "unsupported_directive_dropped":
      return "Directives sans champ";
    case "environment_entry_dropped":
      return "Environnement non porté";
    case "no_image_found":
      return "Aucun dépôt d’image";
  }
}

function pasteNoteSentence(name: PasteNoteName): string {
  switch (name) {
    case "nothing_recognised":
      return "Ce collage n’est ni une commande de conteneur, ni un document compose. Le formulaire n’a pas bougé.";
    case "paste_too_large":
      return "Ce collage dépasse la borne de lecture. Il est refusé entier plutôt que lu à moitié : un document coupé préremplirait un formulaire depuis un demi-service.";
    case "single_service_only":
      return "Une définition décrit un processus servi par une image : ni side-car, ni composition. Un seul service a prérempli le formulaire, et les autres sont nommés ici.";
    case "image_pin_dropped":
      return "Le tag ou l’empreinte a été retiré du dépôt : une définition dit d’où les images viennent, un plan dit laquelle court.";
    case "host_side_dropped":
      return "Le côté hôte a été écarté : la machine dérive les chemins hôte du nom du service, et un plan approuvé décide du port local.";
    case "unsupported_directive_dropped":
      return "Ces directives n’ont aucun champ dans une définition et n’ont donc rien porté. Aucune sortie réseau n’est déclarable à ce palier.";
    case "environment_entry_dropped":
      return "Ces entrées n’ont pas de valeur inerte à porter : rien n’est inventé à leur place, et un secret ne se transporte pas.";
    case "no_image_found":
      return "Aucun dépôt d’image n’a été lu dans ce collage : le champ reste à remplir.";
  }
}

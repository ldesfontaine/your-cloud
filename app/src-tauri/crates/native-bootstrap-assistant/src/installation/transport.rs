//! La couture entre la séquence et la session qui parle réellement à la cible.
//!
//! [`super::sequence::Channel`] est un trait pour que l'ordre, le budget, le
//! registre et la destruction du secret soient exerçables sans transport. Ce
//! module est l'autre bout de cette couture : l'implémentation que le produit
//! livre, portée par la [`LiveSession`] de `#52`–`#54`.
//!
//! **Il ne décide rien de l'installation, et ne décide rien du transport.** Il
//! ne fait que traduire, dans un sens puis dans l'autre, deux vocabulaires qui
//! disent la même chose : une commande fixe et une entrée éventuelle s'en vont,
//! un statut et une sortie reviennent. Tout ce qui juge est ailleurs — les cinq
//! juges du palier pour l'état de la machine, la session elle-même pour ce que
//! le transport autorise.
//!
//! **Pourquoi la couture vit ici et non dans la session.** Le module de session
//! ne connaît pas l'installation, et il ne doit pas : il porte l'accès personnel
//! de paliers antérieurs, dont l'audit, qui n'installe rien. Y placer cette
//! implémentation ferait dépendre le transport de ce qu'un appelant en fait, et
//! le jour où une seconde séquence existerait, la session aurait à connaître les
//! deux.
//!
//! ## Ce qui se perd dans la traduction, et pourquoi c'est délibéré
//!
//! Un [`ChannelReport`] porte trois choses ; une [`Answer`] en porte deux. La
//! **sortie d'erreur est écartée**, et ce n'est pas une négligence : aucun juge
//! de ce palier ne la lit. `transfer` l'écrit noir sur blanc — ce qui est jugé
//! est l'empreinte que la cible a calculée sur son propre fichier, et faire
//! dépendre une porte de sécurité du bavardage d'un système serait la rendre
//! sensible à un avertissement de locale. `nodes` va plus loin : `stat` nomme
//! sur sa sortie d'erreur les opérandes qu'il n'a pas pu lire, et le juge
//! refuse quand même sur les lignes **absentes** de la sortie standard, ce qui
//! est la même information sans dépendre du texte.
//!
//! L'écarter **ici**, à la couture, plutôt que dans chaque juge, est ce qui rend
//! la propriété lisible en un endroit : rien de ce que la machine dit sur
//! `stderr` n'atteint une décision de ce palier.

use super::sequence::{Answer, Channel, ChannelError};
use crate::personal_access::elevation::FixedCommand;
use crate::personal_access::session::{ChannelInput, ChannelReport, GuardVerdict, LiveSession};
use std::time::Instant;

/// Ce qu'une séquence retient de ce qu'un canal a rapporté.
///
/// La conversion est une fonction libre, et non un corps enfoui dans
/// l'implémentation ci-dessous, pour la raison que `#151` a nommée : une
/// décision logée dans un type qui exige un transport réel n'est exerçable par
/// aucune suite, et une propriété qu'aucune suite ne peut exercer n'est pas une
/// propriété tenue. Celle-ci est petite — elle choisit ce qui traverse — mais
/// c'est justement le genre de choix qu'on ne remarque plus une fois qu'il est
/// dans une méthode.
pub fn answer_from(report: ChannelReport) -> Answer {
    Answer {
        exit_status: report.exit_status,
        stdout: report.stdout,
    }
}

/// La session réelle, présentée à une séquence sous la seule forme qu'elle
/// connaît.
///
/// Elle emprunte la session plutôt que de la posséder : la session vit avant
/// cette séquence — c'est elle qui a prouvé l'élévation — et elle doit vivre
/// après, pour être fermée explicitement sur le chemin que l'appelant choisit.
/// Une couture qui l'aurait consommée aurait déplacé la fermeture ici, dans le
/// module qui a le moins de raisons de décider quand une session se termine.
pub struct SessionChannel<'a> {
    live: &'a mut LiveSession,
    /// L'échéance de la session, telle que l'App l'a accordée. Elle n'est
    /// pas renouvelée ici, et ne peut pas l'être : elle est capturée une fois,
    /// à la construction, depuis la valeur que l'appelant tient déjà.
    deadline: Instant,
    /// Ce qui fait tomber un canal en cours : expiration ou annulation. Il est
    /// emprunté au même appelant, donc une séquence ne peut pas s'en fabriquer
    /// un plus indulgent.
    guard: &'a (dyn Fn() -> GuardVerdict + Sync),
}

impl<'a> SessionChannel<'a> {
    pub fn new(
        live: &'a mut LiveSession,
        deadline: Instant,
        guard: &'a (dyn Fn() -> GuardVerdict + Sync),
    ) -> Self {
        Self {
            live,
            deadline,
            guard,
        }
    }
}

impl Channel for SessionChannel<'_> {
    /// Un canal, une commande, et ce que la machine a répondu.
    ///
    /// Tout refus du transport devient [`ChannelError`], et c'est exactement ce
    /// que ce type dit : **l'absence de verdict**. Un budget épuisé, une
    /// échéance atteinte, une annulation, un flux qui se coupe — aucun d'eux ne
    /// dit ce que la machine est devenue, et les distinguer ici reviendrait à
    /// laisser la séquence conclure de la panne d'un transport quelque chose
    /// sur l'état d'une cible.
    fn run(
        &mut self,
        command: FixedCommand,
        input: Option<ChannelInput<'_>>,
    ) -> Result<Answer, ChannelError> {
        // La nature de l'entrée traverse la couture TELLE QUELLE : ce module
        // ne la relit pas, ne la traduit pas, et n'a aucun moyen d'en changer
        // — c'est la session qui écrit, et c'est le type qui a décidé.
        self.live
            .run_channel(command, input, self.deadline, self.guard)
            .map(answer_from)
            .map_err(|_| ChannelError)
    }

    /// Présente à la session le budget que la séquence a dérivé.
    ///
    /// **Aucune décision ici**, et c'est délibéré : la garde de `#54` tranche,
    /// depuis sa propre fonction pure. Elle accepte deux états — une session
    /// neuve qui substitue, et une session qui **porte déjà ce chiffre-là**,
    /// puisque l'adoption réelle a eu lieu avant la sonde d'identité, seul
    /// instant où la première règle l'autorise. Elle refuse tout le reste, dont
    /// une session préparée pour une autre action : le refus tombe alors avant
    /// le premier acte plutôt qu'au milieu de la séquence.
    ///
    /// Une version antérieure de cette couture comparait elle-même les deux
    /// chiffres. La mutation qui supprimait la comparaison laissait 475 cas au
    /// vert — aucune suite ne pouvait l'exercer, ce type exigeant une session
    /// réelle. La décision est donc revenue là où elle est exerçable, et la
    /// même mutation rougit désormais.
    fn adopt_budget(&mut self, budget: usize) -> Result<(), ChannelError> {
        self.live
            .adopt_derived_budget(budget)
            .map_err(|_| ChannelError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ce que la séquence voit d'un canal est le statut et la sortie standard,
    /// et rien d'autre.
    ///
    /// Le cas hostile est celui d'une machine bavarde : une commande qui a
    /// réussi tout en écrivant sur `stderr` — un avertissement de locale, une
    /// note d'un système — ne doit pas pouvoir changer un verdict. Elle ne le
    /// peut pas, parce que ces octets ne traversent pas cette fonction.
    #[test]
    fn what_the_sequence_sees_is_the_status_and_the_standard_output_alone() {
        let answer = answer_from(ChannelReport {
            exit_status: 0,
            stdout: b"ce que la machine repond\n".to_vec(),
            stderr: b"Locale not supported, falling back\n".to_vec(),
        });

        assert_eq!(answer.exit_status, 0);
        assert_eq!(answer.stdout, b"ce que la machine repond\n".to_vec());
        // Il n'y a aucun champ où `stderr` pourrait s'être glissé : la forme
        // d'`Answer` est la garantie, et ce test la fige.
        assert_eq!(
            answer,
            Answer {
                exit_status: 0,
                stdout: b"ce que la machine repond\n".to_vec(),
            }
        );
    }

    /// Le statut passe tel quel : la couture ne le traduit pas, ne le
    /// normalise pas, et n'en fait pas un booléen.
    ///
    /// C'est la même discipline que `elevation::elevated` impose à ses
    /// appelants — un booléen laisserait la conclusion à celui qui la rapporte,
    /// et c'est précisément ce que les juges de ce palier refusent.
    #[test]
    fn the_exit_status_crosses_untouched() {
        for status in [0u32, 1, 2, 100, 127, 255] {
            let answer = answer_from(ChannelReport {
                exit_status: status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
            assert_eq!(answer.exit_status, status);
        }
    }

    /// Une sortie vide reste vide, et n'est pas remplacée par une absence.
    ///
    /// La nuance compte pour `nodes`, qui refuse une sortie vide comme
    /// *illisible* plutôt que de la lire comme « tout est absent ». Une couture
    /// qui aurait rendu `None` quelque part aurait fait disparaître cette
    /// distinction avant que le juge puisse la faire.
    #[test]
    fn an_empty_output_stays_an_empty_output() {
        let answer = answer_from(ChannelReport {
            exit_status: 1,
            stdout: Vec::new(),
            stderr: b"stat: cannot statx '/etc/your-cloud/controller.env'\n".to_vec(),
        });

        assert_eq!(answer.exit_status, 1);
        assert!(answer.stdout.is_empty());
    }
}

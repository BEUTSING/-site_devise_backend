<?php

// Déclaration du namespace pour classer cette classe dans le dossier Service
namespace App\Service;

// Import des classes et interfaces nécessaires
use App\Entity\Offres;
use App\Entity\TauxChange;
use App\Entity\User;
use App\Repository\OffresRepository;
use App\Repository\TauxChangeRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class OffresService
{
    // Injection des dépendances via le constructeur (EntityManager + les deux repositories)
    public function __construct(
        private EntityManagerInterface $em,
        private OffresRepository $repository,
        private TauxChangeRepository $tauxChangeRepository
    ) {
    }

    // Récupérer toutes les offres
    public function getAll(): array
    {
        // Appel au repository pour récupérer tous les enregistrements
        $offres = $this->repository->findAll();

        // Si le tableau est vide, on lève une exception
        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        // Retourne le tableau d'objets Offres
        return $offres;
    }

    // Lister les offres filtrées par devise source
    public function getByDeviseSource(string $deviseSource): array
    {
        $offres = $this->repository->findByDeviseSource($deviseSource);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    // Lister les offres filtrées par devise cible
    public function getByDeviseCible(string $deviseCible): array
    {
        $offres = $this->repository->findByDeviseCible($deviseCible);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    // Lister les offres filtrées par devise source ET devise cible
    public function getByBoth(string $source, string $cible): array
    {
        $offres = $this->repository->findBySourceAndCible($source, $cible);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    // Récupérer une seule offre par son identifiant
    public function getOne(int $id): Offres
    {
        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        return $offre;
    }

    // Créer une nouvelle offre à partir des données JSON reçues dans la requête
    public function create(Request $request, ?User $currentUser = null): Offres
    {
        // Décoder le corps JSON de la requête en tableau associatif
        $data = json_decode($request->getContent(), true);

        // Vérifier que le décodage a bien produit un tableau
        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid JSON data');
        }

        // Vérifier la présence des champs obligatoires dans la requête
        foreach (['montant', 'deviseSourceID', 'deviseCible', 'statut'] as $field) {
            if (!array_key_exists($field, $data)) {
                throw new \InvalidArgumentException("The field $field is required");
            }
        }

        // Créer une nouvelle instance de l'entité Offres
        $offre = new Offres();
        $offre->setMontant((string) $data['montant']);
        $offre->setDeviseCible((string) $data['deviseCible']);
        $offre->setStatut((string) $data['statut']);
        $offre->setImage($data['image'] ?? null);

        // Appliquer le taux de change à partir de l'identifiant envoyé
        $this->applyTauxChangeFromId($offre, (int) $data['deviseSourceID']);

        // Lier l'offre à l'utilisateur connecté si fourni
        if ($currentUser) {
            $offre->setUser($currentUser);
        }

        // Sauvegarder l'entité en base via Doctrine
        $this->em->persist($offre);
        $this->em->flush();

        // Retourner l'objet créé (avec ses relations chargées)
        return $offre;
    }

    // Modifier une offre existante identifiée par son id
    public function update(int $id, Request $request, ?User $currentUser = null): Offres
    {
        $data = json_decode($request->getContent(), true);

        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid JSON data');
        }

        // Chercher l'offre dans la base
        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        // Mettre à jour les champs uniquement s'ils sont présents dans la requête
        if (array_key_exists('montant', $data)) {
            $offre->setMontant((string) $data['montant']);
        }

        if (array_key_exists('deviseCible', $data)) {
            $offre->setDeviseCible((string) $data['deviseCible']);
        }

        if (array_key_exists('statut', $data)) {
            $offre->setStatut((string) $data['statut']);
        }

        if (array_key_exists('image', $data)) {
            $offre->setImage($data['image']);
        }

        // Si un nouvel identifiant de taux est envoyé, on met à jour la devise source et le taux
        if (array_key_exists('deviseSourceID', $data)) {
            $this->applyTauxChangeFromId($offre, (int) $data['deviseSourceID']);
        }

        // Enregistrer les modifications en base
        $this->em->flush();

        return $offre;
    }

    // Supprimer une offre par son identifiant
    public function delete(int $id): array
    {
        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        // Supprimer l'entité de la base
        $this->em->remove($offre);
        $this->em->flush();

        // Retourner un message de confirmation
        return ['message' => 'Offre deleted successfully'];
    }

    // Méthode privée : lier une offre à un taux de change existant grâce à son id
    private function applyTauxChangeFromId(Offres $offre, int $tauxChangeId): void
    {
        // Chercher le taux de change correspondant dans la table taux_change
        $tauxChange = $this->tauxChangeRepository->find($tauxChangeId);

        if (!$tauxChange) {
            throw new \InvalidArgumentException('Exchange rate not found for deviseSourceID: ' . $tauxChangeId);
        }

        // Mettre à jour la devise source de l'offre avec la monnaie du taux trouvé
        $offre->setDeviseSource($tauxChange->getMonnaie());
        // Lier l'objet TauxChange à l'offre
        $offre->setTauxChange($tauxChange);
        // Stocker aussi le taux directement dans l'offre pour faciliter l'affichage
        $offre->setTaux($tauxChange->getTaux());
    }
}

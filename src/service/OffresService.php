<?php

namespace App\Service;

use App\Entity\Offres;
use App\Entity\TauxChange;
use App\Repository\OffresRepository;
use App\Repository\TauxChangeRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class OffresService
{
    private EntityManagerInterface $em;
    private OffresRepository $repository;
    private TauxChangeRepository $tauxChangeRepository;

    public function __construct(EntityManagerInterface $em, OffresRepository $repository, TauxChangeRepository $tauxChangeRepository)
    {
        $this->em = $em;
        $this->repository = $repository;
        $this->tauxChangeRepository = $tauxChangeRepository;
    }

    public function getAll(): array
    {
        $offres = $this->repository->findAll();

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    public function getByDeviseSource(string $deviseSource): array
    {
        $offres = $this->repository->findByDeviseSource($deviseSource);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    public function getByDeviseCible(string $deviseCible): array
    {
        $offres = $this->repository->findByDeviseCible($deviseCible);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    public function getByBoth(string $source, string $cible): array
    {
        $offres = $this->repository->findBySourceAndCible($source, $cible);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    public function getOne(int $id): Offres
    {
        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        return $offre;
    }

    public function create(Request $request): Offres
    {
        $data = json_decode($request->getContent(), true);

        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid JSON data');
        }

        foreach (['montant', 'deviseSource', 'deviseCible', 'statut'] as $field) {
            if (!array_key_exists($field, $data)) {
                throw new \InvalidArgumentException("The field $field is required");
            }
        }

        $offre = new Offres();
        $offre->setMontant((string) $data['montant']);
        $offre->setDeviseSource((string) $data['deviseSource']);
        $offre->setDeviseCible((string) $data['deviseCible']);
        $offre->setStatut((string) $data['statut']);
        $offre->setImage(array_key_exists('image', $data) ? $data['image'] : null);

        $this->applyTauxChange($offre, $data);

        if (!$offre->getTauxChange()) {
            throw new \InvalidArgumentException('The field tauxChange or monnaie is required');
        }

        $this->em->persist($offre);
        $this->em->flush();

        return $offre;
    }

    public function update(int $id, Request $request): Offres
    {
        $data = json_decode($request->getContent(), true);

        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid JSON data');
        }

        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        if (array_key_exists('montant', $data)) {
            $offre->setMontant((string) $data['montant']);
        }

        if (array_key_exists('deviseSource', $data)) {
            $offre->setDeviseSource((string) $data['deviseSource']);
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

        $this->applyTauxChange($offre, $data);

        $this->em->flush();

        return $offre;
    }

    public function delete(int $id): array
    {
        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        $this->em->remove($offre);
        $this->em->flush();

        return ['message' => 'Offre deleted successfully'];
    }

    private function applyTauxChange(Offres $offre, array $data): void
    {
        $tauxChange = $this->resolveTauxChange($data);

        if ($tauxChange instanceof TauxChange) {
            $deviseSource = strtoupper(trim($offre->getDeviseSource() ?? ''));
            if ($deviseSource !== '' && $deviseSource !== $tauxChange->getMonnaie()) {
                throw new \InvalidArgumentException('The selected exchange rate does not match deviseSource');
            }

            $offre->setTauxChange($tauxChange);
            $offre->setTaux($tauxChange->getTaux());

            return;
        }

        if (array_key_exists('taux', $data)) {
            throw new \InvalidArgumentException('The entered rate does not match the selected source currency');
        }
    }

    private function resolveTauxChange(array $data): ?TauxChange
    {
        $tauxChangeId = $data['tauxChange'] ?? $data['tauxChangeId'] ?? null;
        if ($tauxChangeId !== null) {
            $tauxChange = $this->tauxChangeRepository->find((int) $tauxChangeId);
            if (!$tauxChange) {
                throw new \InvalidArgumentException('Exchange rate not found');
            }

            return $tauxChange;
        }

        if (array_key_exists('monnaie', $data)) {
            $monnaie = strtoupper(trim((string) $data['monnaie']));
            if ($monnaie === '') {
                throw new \InvalidArgumentException('The field monnaie is required');
            }

            $tauxChange = $this->tauxChangeRepository->findOneByMonnaieIgnoreCase($monnaie);
            if (!$tauxChange) {
                throw new \InvalidArgumentException('Exchange rate not found');
            }

            return $tauxChange;
        }

        return null;
    }
}

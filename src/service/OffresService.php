<?php

namespace App\Service;

use App\Entity\Offres;
use App\Repository\OffresRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class OffresService
{
    private EntityManagerInterface $em;
    private OffresRepository $repository;

    public function __construct(EntityManagerInterface $em, OffresRepository $repository)
    {
        $this->em = $em;
        $this->repository = $repository;
    }

    // LIST
    public function getAll(): array
    {
        $offres = $this->repository->findAll();

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    // GET BY deviseSource
    public function getByDeviseSource(string $deviseSource): array
    {
        $offres = $this->repository->findByDeviseSource($deviseSource);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    // GET BY deviseCible
    public function getByDeviseCible(string $deviseCible): array
    {
        $offres = $this->repository->findByDeviseCible($deviseCible);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }

    // GET BY BOTH
    public function getByBoth(string $source, string $cible): array
    {
        $offres = $this->repository->findBySourceAndCible($source, $cible);

        if (!$offres) {
            throw new \RuntimeException('No offres found');
        }

        return $offres;
    }
    // CREATE
    public function create(Request $request): Offres
    {
        $data = json_decode($request->getContent(), true);
        if (!$data) {
            throw new \InvalidArgumentException("Invalid JSON data");
        }
        $required = ['montant', 'deviseSource', 'deviseCible', 'taux', 'statut'];

        foreach ($required as $field) {
            if (!isset($data[$field])) {
                throw new \InvalidArgumentException("The field $field is required");
            }
        }

        $offre = new Offres();
        $offre->setMontant($data['montant']);
        $offre->setDeviseSource($data['deviseSource']);
        $offre->setDeviseCible($data['deviseCible']);
        $offre->setTaux($data['taux']);
        $offre->setStatut($data['statut']);
        $offre->setImage($data['image'] ?? null);

        $this->em->persist($offre);
        $this->em->flush();

        return  $offre;
    }

    // UPDATE
    public function update(int $id, Request $request): Offres
    {
        $data = json_decode($request->getContent(), true);

        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        if (isset($data['montant'])) {
            $offre->setMontant($data['montant']);
        }

        if (isset($data['deviseSource'])) {
            $offre->setDeviseSource($data['deviseSource']);
        }

        if (isset($data['deviseCible'])) {
            $offre->setDeviseCible($data['deviseCible']);
        }

        if (isset($data['taux'])) {
            $offre->setTaux($data['taux']);
        }

        if (isset($data['statut'])) {
            $offre->setStatut($data['statut']);
        }

        if (isset($data['image'])) {
            $offre->setImage($data['image']);
        }

        $this->em->flush();

        return $offre;
    }

    // DELETE
    public function delete(int $id): string
    {
        $offre = $this->repository->find($id);

        if (!$offre) {
            throw new \InvalidArgumentException('Offre not found');
        }

        $this->em->remove($offre);
        $this->em->flush();

        return 'Offre deleted successfully';
    }

}
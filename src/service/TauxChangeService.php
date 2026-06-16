<?php

namespace App\Service;

use App\Entity\TauxChange;
use App\Repository\TauxChangeRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class TauxChangeService
{
    private EntityManagerInterface $em;
    private TauxChangeRepository $repository;

    public function __construct(EntityManagerInterface $em, TauxChangeRepository $repository)
    {
        $this->em = $em;
        $this->repository = $repository;
    }

    public function getAll(): array
    {
        $tauxChanges = $this->repository->findAll();

        if (!$tauxChanges) {
            throw new \RuntimeException('No exchange rates found');
        }

        return $tauxChanges;
    }

    public function getByMonnaie(string $monnaie): TauxChange
    {
        $monnaie = $this->normalizeMonnaie($monnaie);
        $tauxChange = $this->repository->findOneByMonnaieIgnoreCase($monnaie);

        if (!$tauxChange) {
            throw new \InvalidArgumentException('Exchange rate not found');
        }

        return $tauxChange;
    }

    public function create(Request $request): TauxChange
    {
        $data = json_decode($request->getContent(), true);

        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid JSON data');
        }

        foreach (['monnaie', 'taux'] as $field) {
            if (!array_key_exists($field, $data)) {
                throw new \InvalidArgumentException("The field $field is required");
            }
        }

        $monnaie = $this->normalizeMonnaie((string) $data['monnaie']);
        if ($monnaie === '') {
            throw new \InvalidArgumentException('The field monnaie is required');
        }

        if ($this->repository->findOneByMonnaieIgnoreCase($monnaie)) {
            throw new \RuntimeException('Exchange rate already exists');
        }

        $tauxChange = new TauxChange();
        $tauxChange->setMonnaie($monnaie);
        $tauxChange->setTaux($this->normalizeTaux($data['taux']));

        $this->em->persist($tauxChange);
        $this->em->flush();

        return $tauxChange;
    }

    public function update(int $id, Request $request): TauxChange
    {
        $data = json_decode($request->getContent(), true);

        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid JSON data');
        }

        $tauxChange = $this->repository->find($id);

        if (!$tauxChange) {
            throw new \InvalidArgumentException('Exchange rate not found');
        }

        if (array_key_exists('monnaie', $data)) {
            $monnaie = $this->normalizeMonnaie((string) $data['monnaie']);
            if ($monnaie === '') {
                throw new \InvalidArgumentException('The field monnaie is required');
            }

            $existingTauxChange = $this->repository->findOneByMonnaieIgnoreCase($monnaie);
            if ($existingTauxChange && $existingTauxChange->getId() !== $id) {
                throw new \RuntimeException('Exchange rate already exists');
            }

            $tauxChange->setMonnaie($monnaie);
        }

        if (array_key_exists('taux', $data)) {
            $tauxChange->setTaux($this->normalizeTaux($data['taux']));
        }

        $this->em->flush();

        return $tauxChange;
    }

    public function delete(int $id): string
    {
        $tauxChange = $this->repository->find($id);

        if (!$tauxChange) {
            throw new \InvalidArgumentException('Exchange rate not found');
        }

        $this->em->remove($tauxChange);
        $this->em->flush();

        return 'Exchange rate deleted successfully';
    }

    private function normalizeMonnaie(string $monnaie): string
    {
        return strtoupper(trim($monnaie));
    }

    private function normalizeTaux(mixed $taux): string
    {
        if (!is_numeric($taux) || (float) $taux <= 0) {
            throw new \InvalidArgumentException('The field taux must be a positive number');
        }

        return (string) $taux;
    }
}

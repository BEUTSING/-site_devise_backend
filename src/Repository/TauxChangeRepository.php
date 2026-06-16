<?php

namespace App\Repository;

use App\Entity\TauxChange;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<TauxChange>
 */
class TauxChangeRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, TauxChange::class);
    }

    public function findOneByMonnaieIgnoreCase(string $monnaie): ?TauxChange
    {
        return $this->createQueryBuilder('t')
            ->where('LOWER(t.monnaie) = LOWER(:monnaie)')
            ->setParameter('monnaie', $monnaie)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

    public function findByMonnaieIgnoreCase(string $monnaie): array
    {
        return $this->createQueryBuilder('t')
            ->where('LOWER(t.monnaie) = LOWER(:monnaie)')
            ->setParameter('monnaie', $monnaie)
            ->orderBy('t.monnaie', 'ASC')
            ->getQuery()
            ->getResult();
    }
}

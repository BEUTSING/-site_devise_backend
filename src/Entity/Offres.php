<?php

namespace App\Entity;

use App\Traits\TimestampableTrait;
use App\Repository\OffresRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: OffresRepository::class)]
#[ORM\HasLifecycleCallbacks]
class Offres
{
    use TimestampableTrait;
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: Types::DECIMAL, precision: 10, scale: 2)]
    private ?string $montant = null;

    #[ORM\Column(length: 255)]
    private ?string $deviseSource = null;

    #[ORM\Column(length: 255)]
    private ?string $deviseCible = null;

    #[ORM\Column(type: Types::DECIMAL, precision: 10, scale: 2)]
    private ?string $taux = null;

    #[ORM\Column(length: 50)]
    private ?string $statut = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $image = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getMontant(): ?string
    {
        return $this->montant;
    }

    public function setMontant(string $montant): static
    {
        $this->montant = $montant;

        return $this;
    }

    public function getDeviseSource(): ?string
    {
        return $this->deviseSource;
    }

    public function setDeviseSource(string $deviseSource): static
    {
        $this->deviseSource = $deviseSource;

        return $this;
    }

    public function getDeviseCible(): ?string
    {
        return $this->deviseCible;
    }

    public function setDeviseCible(string $deviseCible): static
    {
        $this->deviseCible = $deviseCible;

        return $this;
    }

    public function getTaux(): ?string
    {
        return $this->taux;
    }

    public function setTaux(string $taux): static
    {
        $this->taux = $taux;

        return $this;
    }

    public function getStatut(): ?string
    {
        return $this->statut;
    }

    public function setStatut(string $statut): static
    {
        $this->statut = $statut;

        return $this;
    }

    public function getImage(): ?string
    {
        return $this->image;
    }

    public function setImage(?string $image): static
    {
        $this->image = $image;

        return $this;
    }
}

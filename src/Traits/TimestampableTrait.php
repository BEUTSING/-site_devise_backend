<?php

namespace App\Traits;

use Doctrine\ORM\Mapping as ORM;


trait TimestampableTrait
{
  #[ORM\Column]
  private ?\DateTimeImmutable $createdAt = null;

  #[ORM\Column(nullable: true)]
  private ?\DateTimeImmutable $updatedAt = null;

  #[ORM\PreUpdate]
  #[ORM\PrePersist]
  public function setDateValues(): void
  {
    $this->updatedAt = new \DateTimeImmutable();
    if (empty($this->id)) {
      $this->createdAt = new \DateTimeImmutable();
    }
  }

  public function getCreatedAt(): ?\DateTimeImmutable
  {
    return $this->createdAt;
  }

  public function setCreatedAt(\DateTimeImmutable $createdAt): static
  {
    $this->createdAt = $createdAt;

    return $this;
  }

  public function getUpdatedAt(): ?\DateTimeImmutable
  {
    return $this->updatedAt;
  }

  public function setUpdatedAt(?\DateTimeImmutable $updatedAt): static
  {
    $this->updatedAt = $updatedAt;

    return $this;
  }
}

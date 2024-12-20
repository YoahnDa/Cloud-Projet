<?php

namespace App\Entity;

use App\Repository\AuthPinRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: AuthPinRepository::class)]
class AuthPin
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $hashed_pin = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $expiredAt = null;

    #[ORM\Column]
    private ?bool $isUsed = null;

    #[ORM\ManyToOne(inversedBy: 'authPins')]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $userId = null;

    #[ORM\Column(length: 255)]
    private ?string $sessionUid = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getHashedPin(): ?string
    {
        return $this->hashed_pin;
    }

    public function setHashedPin(string $hashed_pin): static
    {
        $this->hashed_pin = $hashed_pin;

        return $this;
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

    public function getExpiredAt(): ?\DateTimeImmutable
    {
        return $this->expiredAt;
    }

    public function setExpiredAt(\DateTimeImmutable $expiredAt): static
    {
        $this->expiredAt = $expiredAt;

        return $this;
    }

    public function isUsed(): ?bool
    {
        return $this->isUsed;
    }

    public function setUsed(bool $is_used): static
    {
        $this->isUsed = $is_used;

        return $this;
    }

    public function getUserId(): ?User
    {
        return $this->userId;
    }

    public function setUserId(?User $userId): static
    {
        $this->userId = $userId;

        return $this;
    }

    public function getSessionUid(): ?string
    {
        return $this->sessionUid;
    }

    public function setSessionUid(string $sessionUid): static
    {
        $this->sessionUid = $sessionUid;

        return $this;
    }
}

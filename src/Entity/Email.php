<?php

namespace App\Entity;

use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Serializer\Annotation\Groups;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use App\Repository\EmailRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: EmailRepository::class)]
#[UniqueEntity(fields: ['value'], message: 'Cet email est déjà utilisé.')]
class Email
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(options :['default' => false])]
    private ?bool $isVerified = false;

    #[ORM\Column(length: 255 , unique: true)]
    #[Assert\Email(message: 'Veuillez entrer un email valide.')]
    #[Assert\NotBlank(message: "Email obligatoire")]
    #[Groups(["getUser"])]
    private ?string $value = null;

    #[ORM\OneToOne(mappedBy: 'idEmail', cascade: ['persist', 'remove'])]
    private ?User $users = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function isVerified(): ?bool
    {
        return $this->isVerified;
    }

    public function setVerified(bool $isVerified): static
    {
        $this->isVerified = $isVerified;

        return $this;
    }

    public function getValue(): ?string
    {
        return $this->value;
    }

    public function setValue(string $value): static
    {
        $this->value = $value;

        return $this;
    }

    public function getUsers(): ?User
    {
        return $this->users;
    }

    public function setUsers(User $users): static
    {
        // set the owning side of the relation if necessary
        if ($users->getIdEmail() !== $this) {
            $users->setIdEmail($this);
        }

        $this->users = $users;

        return $this;
    }
}

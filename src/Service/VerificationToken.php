<?php

namespace App\Service;

use App\Entity\User;
use App\Repository\AuthPinRepository;
use App\Repository\TokenRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class VerificationToken
{
    public function verifyToken(Request $request, TokenRepository $tokenRepos): ?User
    {
        $bearerToken = $request->headers->get('Authorization');

        if ($bearerToken) {
            $bearerToken = str_replace('Bearer ', '', $bearerToken);
            $token = $tokenRepos->findTokenAuth($bearerToken);
            if (!$token) {
                return null;
            }
            return $token->getIdUser();
        }
        return null;
    }

    public function desactivePinToken(string $sessionUid, User $user, AuthPinRepository $authPin, EntityManagerInterface $entity)
    {
        $pinToken = $authPin->findAllValidPinSession($sessionUid);
        foreach ($pinToken as $pin) {
            if (($pin->getUserId())->getId() == $user->getId()) {
                $pin->setUsed(true);
                $entity->persist($pin);
                $entity->flush();
            }
        }
    }
}

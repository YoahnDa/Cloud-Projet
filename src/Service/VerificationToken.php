<?php

namespace App\Service;

use App\Entity\User;
use App\Repository\TokenRepository;
use Symfony\Component\HttpFoundation\Request;

class VerificationToken{
    public function verifyToken(Request $request , TokenRepository $tokenRepos): ?User
    {
        $bearerToken = $request->headers->get('Authorization');

        if ($bearerToken) {
            $bearerToken = str_replace('Bearer ', '', $bearerToken);
            $token = $tokenRepos->findTokenAuth($bearerToken);
            if(!$token){
                return null;
            }
            return $token->getIdUser();
        } 
        return null;
    }
}
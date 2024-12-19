<?php

namespace App\Controller\Api;

use App\Entity\Email;
use App\Entity\Token;
use App\Entity\User;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class InscriptionController extends AbstractController
{



    #[Route('/api/inscription', name: 'app_api_inscription')]
    public function inscription(Request $request , ValidatorInterface $validator , UserPasswordHasherInterface $passwordEncoder , SerializerInterface $serializer , JWTManager $jwtManager , EntityManagerInterface $entity): JsonResponse
    {
        $email = new Email();
        $email->setValue($request->get('email'));
        $email->setVerified(false);

        $errorEmail = $validator->validate($email); 

        if($errorEmail->count() > 0){
            return new JsonResponse($serializer->serialize($errorEmail, 'json'), JsonResponse::HTTP_BAD_REQUEST, [], true);
        }

        $user = new User();
        $user->setIdEmail($email);
        $user->setRoles(["ROLE_USER"]);
        $user->setPassword($passwordEncoder->hashPassword($user,$request->get('password')));
        $user->setUsername($request->request->get('nom'));

        $errorUser = $validator->validate($user);

        if($errorUser->count() > 0){
            return new JsonResponse($serializer->serialize($errorUser, 'json'), JsonResponse::HTTP_BAD_REQUEST, [], true);
        }

        $customTTL = 3600; // Exemple d'une durée de 1 heure par défaut
    
        // Calculer la date d'expiration personnalisée
        $expireAt = new DateTimeImmutable();
        $expireAt = $expireAt->modify("+$customTTL seconds");
    
        // Créer un payload avec une durée d'expiration dynamique
        $payload = [
            'exp' => $expireAt->getTimestamp(),
        ];

        $token = $jwtManager->create($user,$payload);
        $dates = new DateTimeImmutable();
        $tokens = new Token();

        $tokens->setIdUser($user);
        $tokens->setToken($token);
        $tokens->setCreatedAt($dates);

        $entity->persist($user);
        $entity->persist($email);
        $entity->persist($tokens);

        $entity->flush();

        return new JsonResponse(['message' => 'Un email envoyer à '. $email->getValue()],Response::HTTP_OK, [], true);
    }
}

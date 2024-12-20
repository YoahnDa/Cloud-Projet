<?php

namespace App\Controller\Api;

use App\Entity\Email as EntityEmail;
use Symfony\Component\Mime\Email; // pour le composant Mailer
use App\Entity\Token;
use App\Entity\User;
use App\Repository\TokenRepository;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;

class InscriptionController extends AbstractController
{

    /**
     * Insertion des information pour avoir l'email de confirmation.
     * 
     * @Route("/api/inscription", name="app_api_inscription", methods={"POST"})
     * @OA\Post(
     *     path="/api/inscription",
     *     summary="Inscription d'un utilisateur",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", example="user@example.com"),
     *             @OA\Property(property="password", type="string", example="password123"),
     *             @OA\Property(property="username", type="string", example="username123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Email de vérification envoyé.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Un email envoyer à user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Validation échouée.",
     *         @OA\JsonContent(type="object")
     *     )
     * )
     */
    #[Route('/api/inscription', name: 'app_api_inscription', methods : ['POST'])]
    public function inscription(Request $request , ValidatorInterface $validator , UserPasswordHasherInterface $passwordEncoder , SerializerInterface $serializer , JWTTokenManagerInterface $jwtManager , EntityManagerInterface $entity , UrlGeneratorInterface $urlGenerator , MailerInterface $mailer): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        $email = new EntityEmail();
        $email->setValue($data['email'] ? $data['email'] : null);
        $email->setVerified(false);

        $errorEmail = $validator->validate($email); 

        if($errorEmail->count() > 0){
            return new JsonResponse($serializer->serialize($errorEmail, 'json'), JsonResponse::HTTP_BAD_REQUEST, [] , true);
        }

        $user = new User();
        $user->setIdEmail($email);
        $user->setRoles(["ROLE_USER"]);
        $user->setPassword($passwordEncoder->hashPassword($user,$data['password'] ? $data['password'] : ''));
        $user->setUsername($data['username'] ? $data['username'] : '');

        $errorUser = $validator->validate($user);

        if($errorUser->count() > 0){
            return new JsonResponse($serializer->serialize($errorUser, 'json'), JsonResponse::HTTP_BAD_REQUEST, [] , true);
        }

        $entity->persist($email);
        $entity->persist($user);
        $entity->flush();

        $dateCreate = new \DateTimeImmutable();
        $dateExpired = $dateCreate->modify('+1 hour');

        $payload = [
            'id' => $user->getId(),
            'isUsed' => false,
            'iat' => $dateCreate->getTimestamp(),
            'exp' => $dateExpired->getTimestamp(),
        ];

        $token = $jwtManager->createFromPayload($user,$payload);

        $tokens = new Token();

        $tokens->setIdUser($user);
        $tokens->setToken($token);
        $tokens->setCreatedAt($dateCreate);
        $tokens->setExpiredAt($dateExpired);

        $entity->persist($tokens);
        
        $entity->flush();

        $location = $urlGenerator->generate('app_api_verification', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

        $emailMessage = (new Email())
            ->from('yoahndaniel37@gmail.com')
            ->to($email->getValue())
            ->subject('Vérification de votre compte !')
            ->text('Veuillez copier ce lien àfin d\'activer votre compte '.$location);

        $mailer->send($emailMessage);
        return new JsonResponse(['message' => 'Un email envoyer à '. $email->getValue()],Response::HTTP_OK, []);
    }

    /**
     *  Verification de l'email.
     * @Route("/api/verification/{token}", name="app_api_verification", methods={"GET"})
     * @OA\Get(
     *     path="/api/verification/{token}",
     *     summary="Vérification d'un email via un token",
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         description="Token de vérification",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=202,
     *         description="Email validé avec succès.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Votre email a été bien validé.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Erreur de validation ou expiration.",
     *         @OA\JsonContent(type="object")
     *     )
     * )
     */
    #[Route('/api/verification/{token}', name: 'app_api_verification' , methods:['GET'])]
    public function verification(Request $request , JWTTokenManagerInterface $jwtManager , EntityManagerInterface $entity): JsonResponse
    {
        $token = $request->get('token');

        if(!$token) {
            return new JsonResponse(['error' => 'L\'url est endommagé.'], JsonResponse::HTTP_BAD_REQUEST);
        }

        $tokenBase = $entity->getRepository(Token::class)->findValidToken($token,'VER');

        if(!$tokenBase) {
            return new JsonResponse(['error' => 'Token non valide'], JsonResponse::HTTP_BAD_REQUEST);
        }

        $userReal = $tokenBase->getIdUser();

        // Obtenir le timestamp actuel
        $dateCreate = new DateTimeImmutable();
        $currentTimestamp = time();
        $expirationTimestamp = ($tokenBase->getExpiredAt())->getTimestamp();

        // Vérifier si le token est expiré
        if ($currentTimestamp > $expirationTimestamp) {
            return new JsonResponse(['error' => 'Token est expiré.'], JsonResponse::HTTP_BAD_REQUEST);
        }

        if(($userReal->getIdEmail())->isVerified()){
            return new JsonResponse(['error' => 'Votre email a déjà été validé.'], JsonResponse::HTTP_BAD_REQUEST);
        }

        ($userReal->getIdEmail())->setVerified(true);

        $newPayload = [
            'id' => $userReal->getId(),
            'isUsed' => true,
            'exp' => $expirationTimestamp,
            'iat' => ($tokenBase->getCreatedAt())->getTimestamp()
        ];

        if(!($entity->getRepository(Token::class)->findAuthToken($userReal))){
            $payLoadAuth = [
                'id' => $userReal->getId(),
                'iat' => $dateCreate->getTimestamp()
            ];
    
            $tokenAuth = new Token();
            $tokenAuth->setIdUser($userReal);
            $tokenAuth->setType('AUTH');
            $tokenAuth->setCreatedAt($dateCreate);
            $tokenAuth->setToken($jwtManager->createFromPayload($userReal,$payLoadAuth));

            $entity->persist($tokenAuth);
        }

        $tokenNew = $jwtManager->createFromPayload($userReal,$newPayload);
        $tokenBase -> setToken($tokenNew);

        $entity->persist($userReal);
        $entity->persist($tokenBase);
        $entity->flush();

        return new JsonResponse(['message' => 'Votre email a été bien valider.'], JsonResponse::HTTP_ACCEPTED);
    }
}

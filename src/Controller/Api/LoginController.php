<?php

namespace App\Controller\Api;

use App\Entity\AuthPin;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mime\Email;
use App\Entity\Token;
use App\Repository\AuthPinRepository;
use App\Repository\TokenRepository;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Nelmio\ApiDocBundle\Annotation\Model;
use Nelmio\ApiDocBundle\Annotation\Security;
use OpenApi\Annotations as OA;

class LoginController extends AbstractController
{
    /**
     * Authentification initiale via email avec envoi d'un PIN.
     *
     * @OA\Post(
     *     path="/api/login",
     *     summary="Envoie un email pour confirmation avec un PIN",
     *     tags={"Authentification"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="username", type="string", description="Nom d'utilisateur"),
     *             @OA\Property(property="password", type="string", description="Mot de passe")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Email envoyé avec succès",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Email envoyé à user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Nom d'utilisateur ou mot de passe manquant",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="error", type="string", example="Username or password missing")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Utilisateur non autorisé",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="error", type="string", example="Utilisateur ou mot de passe invalide.")
     *         )
     *     )
     * )
     */
    #[Route('/api/login', name: 'app_api_login', methods: ['POST'])]
    public function login(Request $request, EntityManagerInterface $entity, UserRepository $userRepos, AuthPinRepository $authRepos, UserPasswordHasherInterface $passwordEncoder, JWTTokenManagerInterface $jwtManager, MailerInterface $mailer, UrlGeneratorInterface $urlGen , PasswordHasherFactoryInterface $passCrypt): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $username = $data['username'] ?? null;
        $password = $data['password'] ?? null;
    
        if (!$username || !$password) {
            return new JsonResponse(['error' => 'Username or password missing'], Response::HTTP_BAD_REQUEST);
        }
    
        // Rechercher l'utilisateur en base de données
        $user = $userRepos->findOneByUsername($username);
        if ($user) {
            if ($user->getTentative() >= 3) {
                return new JsonResponse(['error' => 'Vous avez atteint la limite de tentative. Veuillez réinitialiser vos nombres de tentatives.'], Response::HTTP_UNAUTHORIZED);
            } else if (!(($user->getIdEmail())->isVerified())) {
                return new JsonResponse(['error' => 'Votre compte n\'est pas vérifié'], Response::HTTP_UNAUTHORIZED);
            }
        }
    
        if (!$user || !$passwordEncoder->isPasswordValid($user, $password)) {
            if ($user) {
                $user->setTentative($user->getTentative() + 1);
                $entity->persist($user);
                $entity->flush();
            }
            return new JsonResponse(['error' => 'Utilisateur ou mot de passe invalide.'], Response::HTTP_UNAUTHORIZED);
        }

        $pin = random_int(10000, 99999); 
    
        $dateCreate = new DateTimeImmutable();

        $sessionUid = uniqid('session_',true);

        $session = $request -> getSession();

        if (!($session->has('session_id'))) {
            $session->set('session_id', $sessionUid);
        }else{
            $sessionId = $session->get('session_id');
            $authPin = $authRepos -> findValidPinForSession($sessionId);
            if($authPin){
                return new JsonResponse(['error' => 'Vous avez encore un code PIN valide.'], Response::HTTP_UNAUTHORIZED);
            }
        }

        $hasher = $passCrypt->getPasswordHasher(AuthPin::class);
        $tokenPin = new AuthPin();
        $tokenPin->setUserId($user);
        $tokenPin->setCreatedAt($dateCreate);
        $tokenPin->setExpiredAt($dateCreate->modify('+90 seconds')); 
        $tokenPin->setHashedPin($hasher->hash($pin));
        $tokenPin->setUsed(false);
        $tokenPin->setSessionUid($session->get('session_id'));
    
        $entity->persist($tokenPin);
        $entity->flush();
    
        $location = $urlGen->generate('app_api_pin_verification', [], UrlGeneratorInterface::ABSOLUTE_URL);
    
        $emailMessage = (new Email())
            ->from('yoahndaniel37@gmail.com')
            ->to(($user->getIdEmail())->getValue())
            ->subject('Vérification de votre compte !')
            ->text('Voici votre code à double authentification: ' . $pin . '.\nVeuillez l\'insérer sur ce lien ' . $location);
    
        $mailer->send($emailMessage);
    
        return new JsonResponse(['message' => 'Email envoyé à ' . ($user->getIdEmail())->getValue()], Response::HTTP_OK);
    }
    

    /**
     * Vérification du code PIN pour la deuxième authentification.
     *
     * @OA\Post(
     *     path="/api/pin_verification",
     *     summary="Vérifie le code PIN pour authentification",
     *     tags={"Authentification"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="pin", type="integer", description="Le code PIN fourni par l'utilisateur")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Authentification réussie avec retour du token JWT",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="token", type="string", example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="PIN invalide ou expiré",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="error", type="string", example="PIN invalide ou expiré.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Erreur interne du serveur",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="error", type="string", example="PIN Invalide.")
     *         )
     *     )
     * )
     */
    #[Route('/api/pin_verification', name: 'app_api_pin_verification' , methods : ['POST'])]
    public function pin_verify(Request $request , EntityManagerInterface $entity , PasswordHasherFactoryInterface $factory , AuthPinRepository $authRepos , TokenRepository $tokenRepos , JWTTokenManagerInterface $jwtManager): JsonResponse
    {
        $data =  $data = json_decode($request->getContent(), true);
        if(!$data['pin']) {
            return new JsonResponse(['error' => 'PIN Invalide.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $session = $request -> getSession();

        if (!$session->has('session_id')) {
            return new JsonResponse(['error' => 'Vous vous êtes pas encore connecté.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $sessionUid = $session->get('session_id');

        $pinAuth = $authRepos -> findValidPinForSession($sessionUid);

        if(!$pinAuth){
            return new JsonResponse(['error' => 'PIN Expiré ou Inexistante.'.$sessionUid], Response::HTTP_UNAUTHORIZED);
        }

        $user = $pinAuth->getUserId();

        if($user->getTentative()>=3){
            return new JsonResponse(['error' => 'Nombres de tentatives limités.'], Response::HTTP_UNAUTHORIZED);
        }

        $hasher = $factory->getPasswordHasher(AuthPin::class);

        $authentification = $hasher -> verify($pinAuth->getHashedPin(),$data['pin']);

        if(!$authentification){
            $user->setTentative($user->getTentative() + 1);
            $entity->persist($user);
            $pinAuth->setUsed(true);
            $entity->persist($pinAuth);
            $entity->flush();
            return new JsonResponse(['error' => 'PIN Invalide.'], Response::HTTP_UNAUTHORIZED);
        }

        $user->setTentative(0);
        $entity->persist($user);
        $pinAuth->setUsed(true);
        $entity->persist($pinAuth);
        $entity->flush();

        $token = $tokenRepos->findAuthToken($user);
        if (!$token) {
            $dateCreate = new DateTimeImmutable();
            $payLoadAuth = [
                'id' => $user->getId(),
                'iat' => $dateCreate->getTimestamp()
            ];
    
            $tokenAuth = new Token();
            $tokenAuth->setIdUser($user);
            $tokenAuth->setType('AUTH');
            $tokenAuth->setCreatedAt($dateCreate);
            $tokenAuth->setToken($jwtManager->createFromPayload($user,$payLoadAuth));

            $entity->persist($tokenAuth);
            $entity->flush();
        }

        $customLifetime = 3600;

        ini_set('session.gc_maxlifetime', $customLifetime);
        $params = session_get_cookie_params();
        setcookie(session_name(), session_id(), time() + $customLifetime, $params['path'], $params['domain'], $params['secure'], $params['httponly']);

        return new JsonResponse(['token' => $token->getToken()], Response::HTTP_OK);
    }
}

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
use App\Service\EmailProvider;
use App\Service\VerificationToken;
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

    private $customLifetime = 3600;
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
    public function login(Request $request, TokenRepository $tokenRepos, EntityManagerInterface $entity, UserRepository $userRepos, AuthPinRepository $authRepos, UserPasswordHasherInterface $passwordEncoder, JWTTokenManagerInterface $jwtManager, MailerInterface $mailer, UrlGeneratorInterface $urlGen, PasswordHasherFactoryInterface $passCrypt, EmailProvider $emailProvider): JsonResponse
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
            if ($user->getTentative() > 2) {
                $tokenRein = $tokenRepos->findTokenUser($user, 'REIN');
                if ($tokenRein) {
                    return new JsonResponse(['error' => 'Vous avez atteint la limite de tentative. Veuillez utiliser le lien envoyer à votre email.'], Response::HTTP_UNAUTHORIZED);
                } else {
                    // $verify->desactivePinToken($sessionUid,$user);
                    $emailProvider->sendEmailReinitialisation($mailer, $entity, $jwtManager, $user, $urlGen);
                    return new JsonResponse(['error' => 'Vous avez atteint la limite de tentative. Veuillez consulter le lien envoyer à votre email.'], Response::HTTP_UNAUTHORIZED);
                }
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

        $sessionUid = uniqid('session_', true);

        $session = $request->getSession();

        if (!($session->has('session_id'))) {
            $session->set('session_id', $sessionUid);
        } else {
            $sessionId = $session->get('session_id');
            $authPin = $authRepos->findValidPinForSession($sessionId);
            if ($authPin) {
                return new JsonResponse(['error' => 'Vous avez encore un code PIN valide.'], Response::HTTP_UNAUTHORIZED);
            }
        }
        $emailProvider->sendPinValidation($mailer, $entity, $request, $user, $urlGen, $passCrypt);
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
    #[Route('/api/pin_verification', name: 'app_api_pin_verification', methods: ['POST'])]
    public function pin_verify(Request $request, EntityManagerInterface $entity, PasswordHasherFactoryInterface $factory, AuthPinRepository $authRepos, TokenRepository $tokenRepos, JWTTokenManagerInterface $jwtManager, UrlGeneratorInterface $urlGen, MailerInterface $mailer, EmailProvider $emailProvider , VerificationToken $verify): JsonResponse
    {
        $data =  $data = json_decode($request->getContent(), true);
        if (!$data['pin']) {
            return new JsonResponse(['error' => 'PIN Invalide.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $session = $request->getSession();

        if (!$session->has('session_id')) {
            return new JsonResponse(['error' => 'Vous vous êtes pas encore connecté.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $sessionUid = $session->get('session_id');

        $pinAuth = $authRepos->findValidPinForSession($sessionUid);

        if (!$pinAuth) {
            return new JsonResponse(['error' => 'PIN Expiré ou Inexistante.'], Response::HTTP_UNAUTHORIZED);
        }

        $user = $pinAuth->getUserId();

        if ($user->getTentative() > 2) {
            $tokenRein = $tokenRepos->findTokenUser($user, 'REIN');
            if ($tokenRein) {
                return new JsonResponse(['error' => 'Vous avez atteint la limite de tentative. Veuillez utiliser le lien envoyer à votre email.'], Response::HTTP_UNAUTHORIZED);
            } else {
                $verify->desactivePinToken($sessionUid,$user,$authRepos,$entity);
                $emailProvider->sendEmailReinitialisation($mailer, $entity, $jwtManager, $user, $urlGen);
                return new JsonResponse(['error' => 'Vous avez atteint la limite de tentative. Veuillez consulter le lien envoyer à votre email.'], Response::HTTP_UNAUTHORIZED);
            }
        }

        $hasher = $factory->getPasswordHasher(AuthPin::class);

        $authentification = $hasher->verify($pinAuth->getHashedPin(), $data['pin']);

        if (!$authentification) {
            $user->setTentative($user->getTentative() + 1);
            $entity->persist($user);
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
            $tokenAuth->setToken($jwtManager->createFromPayload($user, $payLoadAuth));

            $entity->persist($tokenAuth);
            $entity->flush();
        }

        if (session_status() == PHP_SESSION_ACTIVE) {
            session_destroy();
        }

        ini_set('session.gc_maxlifetime', $this->customLifetime);
        $params = session_get_cookie_params();
        setcookie(session_name(), session_id(), time() + $this->customLifetime, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        session_start();
        $session = $request->getSession();
        $session->set('session_uid',$sessionUid);

        return new JsonResponse(['token' => $token->getToken()], Response::HTTP_OK);
    }

    /**
     *  Reinitialisation du nombre de tentative de l'email.
     * @Route("/api/reinitialisation/{token}", name="app_api_reinitialisation", methods={"GET"})
     * @OA\Get(
     *     path="/api/reinitialisation/{token}",
     *     summary="Reinitialisation du nombre de tentative via un token",
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         description="Token de reinitialisation",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=202,
     *         description="Email réinitialiser avec succès.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Votre email a été bien reinitialisé.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Erreur de validation ou expiration.",
     *         @OA\JsonContent(type="object")
     *     )
     * )
     */

    #[Route('/api/reinitialisation/{token}', name: 'app_api_reinitialisation', methods: ['GET'])]
    public function reinitialisation(Request $request, JWTTokenManagerInterface $jwtManager, EntityManagerInterface $entity): Response
    {
        $token = $request->get('token');
        $dateExpired = new DateTimeImmutable();

        if (!$token) {
            return $this->render('error/link_error.html.twig' , [
                'message' => 'L\'url est endommagé.',
                'status_code' => JsonResponse::HTTP_BAD_REQUEST
            ]);
        }

        $tokenBase = $entity->getRepository(Token::class)->findValidToken($token, 'REIN');

        if (!$tokenBase) {
            return $this->render('error/link_error.html.twig' , [
                'message' => 'Token de réintialisation non valide ou expiré.',
                'status_code' => JsonResponse::HTTP_BAD_REQUEST
            ]);
        }

        $user = $tokenBase->getIdUser();

        $payload = [
            'id' => $user->getId(),
            'isReinit' => true,
        ];

        $token = $jwtManager->createFromPayload($user, $payload);

        $tokenBase->setToken($token);
        $tokenBase->setExpiredAt($dateExpired);

        $tokenBase -> setUsed(true);

        $entity->persist($tokenBase);
        $user->setTentative(0);
        $entity->persist($user);
        $entity->flush();

        return $this->render('success/link_success.html.twig',[
            'message' => 'Votre lien de réinitialisation a été utilisé avec succès.',
            'description' => 'Vous pouvez maintenant vous connectez !'
        ]);
    }
}

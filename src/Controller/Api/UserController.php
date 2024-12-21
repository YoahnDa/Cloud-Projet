<?php

namespace App\Controller\Api;

use App\Repository\TokenRepository;
use App\Service\VerificationToken;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class UserController extends AbstractController
{
    /**
     * Get les informations de l'utilisateur.
     *
     * @OA\Get(
     *     path="/api/user",
     *     summary="Donne les informations de l'utilisateur",
     *     tags={"Information"}
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Information bien fournie",
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Erreur interne du serveur",
     *     )
     *     @OA\Response(
     *         response=401,
     *         description="Vous n'avez pas l'autorisation.",
     *     )
     * )
     */
    #[Route('/api/user', name: 'app_api_user', methods: ['GET'])]
    public function getInfo(Request $request , TokenRepository $tokenRepos , SerializerInterface $serializer , VerificationToken $verifSecurity): JsonResponse
    {
        $user = $verifSecurity->verifyToken($request,$tokenRepos) ;
        if(!$user){
            return new JsonResponse(['message' => 'Vous n\'avez pas l\'autorisation'], Response::HTTP_UNAUTHORIZED);
        }
        $userJson = $serializer->serialize($user,'json',['groups'=>'getUser']);
        return new JsonResponse($userJson,Response::HTTP_OK,[],true);
    }

    /**
     * Modification des infos utilisateurs.
     *
     * @OA\Put(
     *     path="/api/user",
     *     summary="Modifie les infos user",
     *     tags={"Modification"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="username", type="string", description="Le nouveau username de l'utilisateur"),
     *             @OA\Property(property="password", type="string", description="Le nouveau password de l'utilisateur")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Modification réussi.",
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Vous n'avez pas l'autorisation."
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Erreur interne du serveur"
     *     )
     * )
     */
    #[Route('/api/user', name: 'app_api_user_modify', methods: ['PUT'])]
    public function modifyInfo(Request $request , EntityManagerInterface $entity , TokenRepository $tokenRepos , SerializerInterface $serializer , UserPasswordHasherInterface $passwordEncoder , ValidatorInterface $validator , VerificationToken $verifSecurity): JsonResponse
    {
        $user = $verifSecurity->verifyToken($request,$tokenRepos);

        if(!$user){
            return new JsonResponse(['message' => 'Vous n\'avez pas l\'autorisation'], Response::HTTP_UNAUTHORIZED , [] , true);
        }

        $data = json_decode($request->getContent(),true);

        $username = $data['username'] ?? $user->getUsername();
        $password = $passwordEncoder->hashPassword($user,$data['password'] ? $data['password'] : '') ;
        $user->setUsername($username);
        $user->setPassword($password);

        $errorUser = $validator->validate($user);

        if($errorUser->count() > 0){
            return new JsonResponse($serializer->serialize($errorUser, 'json'), JsonResponse::HTTP_BAD_REQUEST, []);
        }

        $entity->persist($user);
        $entity->flush();

        return new JsonResponse(['message' => 'Information modifié.'],Response::HTTP_ACCEPTED);
    }

    /**
     * Suppression d'un compte utilisateur.
     *
     * @OA\Delete(
     *     path="/api/user",
     *     summary="Supprime un compte",
     *     tags={"Suppression"},
     *     @OA\Response(
     *         response=200,
     *         description="Suppression réussi.",
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Vous n'avez pas l'autorisation."
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Erreur interne du serveur"
     *     )
     * )
     */
    #[Route('/api/user', name: 'app_api_user_delete', methods: ['DELETE'])]
    public function deleteUser(Request $request , EntityManagerInterface $entity , TokenRepository $tokenRepos , VerificationToken $verifSecurity): JsonResponse
    {
        $user = $verifSecurity->verifyToken($request,$tokenRepos) ;
        if(!$user){
            return new JsonResponse(['message' => 'Vous n\'avez pas l\'autorisation'], Response::HTTP_UNAUTHORIZED);
        }

        $entity->remove($user);

        $entity->flush();

        session_destroy();

        return new JsonResponse(['message' => 'Votre compte a été supprimer.'],Response::HTTP_ACCEPTED);
    }
}

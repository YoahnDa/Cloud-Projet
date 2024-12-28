<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ErrorController extends AbstractController
{
    #[Route('/error/expired', name: 'session_error')]
    public function index(): Response
    {
        return $this->render('error/session_error.html.twig', [
            'message' => 'Votre connexion a expiré',
            'description' => 'Vous avez atteint votre limite de temps de connection'
        ]);
    }

    #[Route('/error/not_connected', name: 'connexion_error')]
    public function session_inexistante(): Response
    {
        return $this->render('error/session_error.html.twig', [
            'message' => 'Veuillez vous connectez.',
            'description' => 'Connection introuvable.'
        ]);
    }
}

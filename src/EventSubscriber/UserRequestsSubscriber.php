<?php

namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class UserRequestsSubscriber implements EventSubscriberInterface
{
    private $router;

    public function __construct(UrlGeneratorInterface $router)
    {
        $this->router = $router;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        // Vérifier que l'événement est pour une requête HTTP et que c'est la requête principale
        $request = $event->getRequest();

        // Récupérer le nom du contrôleur et de l'action
        $controller = $request->attributes->get('_controller');

        // Vérifier si le contrôleur est celui auquel on veut appliquer ce listener
        if (strpos($controller, 'App\\Controller\\Api\\UserController') === 0) {
            // Vérifier la session
            $session = $request->getSession();
            // Vérifier si la session existe
            if (!$session) {
                $this->redirectToErrorPage($event, 'session_error');
                return;
            } else if (!$session->has('session_uid')) {
                $this->redirectToErrorPage($event, 'connexion_error');
                return;
            }
        }
        return;
    }

    private function redirectToErrorPage(RequestEvent $event, string $url): void
    {
        // Générer l'URL de la page d'erreur avec le message d'erreur
        $url = $this->router->generate($url); // Route d'erreur à définir

        $response = new RedirectResponse($url);  // Créer une redirection vers l'URL

        $event->setResponse($response);  // Rediriger l'utilisateur vers la page d'erreur
    }

    public static function getSubscribedEvents(): array
    {
        // Écouter l'événement KernelEvents::REQUEST
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
        ];
    }
}


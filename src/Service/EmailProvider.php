<?php 

namespace App\Service;

use App\Entity\AuthPin;
use App\Entity\Token;
use App\Entity\User;
use App\Repository\TokenRepository;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use phpDocumentor\Reflection\Types\Boolean;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use App\Entity\Email as EmailEntity;

class EmailProvider{
    public function sendEmailReinitialisation(Mailer $mailer , EntityManagerInterface $entity,JWTTokenManagerInterface $jwtManager , User $user , UrlGeneratorInterface $urlGen)
    {
        $dateCreate = new DateTimeImmutable();
        $dateExpired = $dateCreate->modify('+120 seconds');

        $payload = [
            'id' => $user->getId(),
            'isReinit' => true,
            'iat' => $dateCreate->getTimestamp(),
            'exp' => $dateExpired->getTimestamp()
        ];

        $token = $jwtManager->createFromPayload($user,$payload);

        $tokens = new Token();

        $tokens->setIdUser($user);
        $tokens->setToken($token);
        $tokens->setType('REIN');
        $tokens->setCreatedAt($dateCreate);
        $tokens->setExpiredAt($dateExpired);

        $entity->persist($tokens);
        
        $entity->flush();

        $location = $location = $urlGen->generate('app_api_reinitialisation', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

        $emailMessage = (new Email())
        ->from('yoahndaniel37@gmail.com')
        ->to(($user->getIdEmail())->getValue())
        ->subject('Réinitialisation du nombres de tentatives !')
        ->text('Veuillez copier ce lien àfin de réactiver votre compte '.$location);

        $mailer->send($emailMessage);
    }

    public function sendPinValidation(Mailer $mailer , EntityManagerInterface $entity,Request $request , User $user , UrlGeneratorInterface $urlGen , PasswordHasherFactoryInterface $passCrypt)
    {
        $dateCreate = new DateTimeImmutable();

        $session = $request->getSession();

        $pin = random_int(10000, 99999); 
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
            ->subject('Vérification à deux facteur !')
            ->text('Voici votre code à double authentification: ' . $pin . '.\nVeuillez l\'insérer sur ce lien ' . $location);
    
        $mailer->send($emailMessage);
    }

    public function sendEmailVerification(Mailer $mailer , EntityManagerInterface $entity,JWTTokenManagerInterface $jwtManager , User $user , UrlGeneratorInterface $urlGen , EmailEntity $email)
    {
        $dateCreate = new DateTimeImmutable();
        $dateExpired = $dateCreate->modify('+180 seconds');

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

        $location = $urlGen->generate('app_api_verification', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

        $emailMessage = (new Email())
            ->from('yoahndaniel37@gmail.com')
            ->to($email->getValue())
            ->subject('Vérification de votre compte !')
            ->text('Veuillez copier ce lien àfin d\'activer votre compte '.$location);

        $mailer->send($emailMessage);
    }
}
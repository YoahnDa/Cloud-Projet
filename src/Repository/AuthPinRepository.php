<?php

namespace App\Repository;

use App\Entity\AuthPin;
use DateTimeImmutable;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<AuthPin>
 */
class AuthPinRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, AuthPin::class);
    }

    public function findValidPinForSession(string $sessionId): ?AuthPin
    {
        $qb = $this->createQueryBuilder('p');

        $qb->where('p.sessionUid = :sessionId')
            ->andWhere('p.expiredAt > :now') // Vérifie que le code n'est pas expiré.
            ->andWhere('p.isUsed = false')  // Vérifie que le code n'a pas été utilisé.
            ->setParameter('sessionId', $sessionId)
            ->setParameter('now', new DateTimeImmutable())
            ->orderBy('p.createdAt', 'DESC')
            ->setMaxResults(1);

        return $qb->getQuery()->getOneOrNullResult();
    }

    public function findAllValidPinSession(string $sessionId): ?AuthPin
    {
        $qb = $this->createQueryBuilder('p');

        $qb->where('p.sessionUid = :sessionId')
            ->andWhere('p.expiredAt > :now') // Vérifie que le code n'est pas expiré.
            ->andWhere('p.isUsed = false')  // Vérifie que le code n'a pas été utilisé.
            ->setParameter('sessionId', $sessionId)
            ->setParameter('now', new DateTimeImmutable())
            ->orderBy('p.createdAt', 'DESC');

        return $qb->getQuery()->getOneOrNullResult();
    }

    //    /**
    //     * @return AuthPin[] Returns an array of AuthPin objects
    //     */
    //    public function findByExampleField($value): array
    //    {
    //        return $this->createQueryBuilder('a')
    //            ->andWhere('a.exampleField = :val')
    //            ->setParameter('val', $value)
    //            ->orderBy('a.id', 'ASC')
    //            ->setMaxResults(10)
    //            ->getQuery()
    //            ->getResult()
    //        ;
    //    }

    //    public function findOneBySomeField($value): ?AuthPin
    //    {
    //        return $this->createQueryBuilder('a')
    //            ->andWhere('a.exampleField = :val')
    //            ->setParameter('val', $value)
    //            ->getQuery()
    //            ->getOneOrNullResult()
    //        ;
    //    }
}

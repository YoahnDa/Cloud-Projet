<?php

namespace App\Repository;

use App\Entity\Token;
use App\Entity\User;
use DateTimeImmutable;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Token>
 */
class TokenRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Token::class);
    }

    public function findValidToken(string $tokenValue,string $type)
    {
        return $this->createQueryBuilder('t')
            ->andWhere('t.token = :token')
            ->andWhere('t.type = :type')
            ->andWhere('t.expiredAt > :now')
            ->andWhere('t.isUsed = false')
            ->setParameter('token', $tokenValue)
            ->setParameter('type', $type)
            ->setParameter('now', new DateTimeImmutable())
            ->getQuery()
            ->getOneOrNullResult();
    }

    public function findTokenUser(User $user , string $type = 'AUTH')
    {
        return $this->createQueryBuilder('t')
            ->andWhere('t.idUser = :user')
            ->andWhere('t.type = :type')
            ->andWhere('t.expiredAt > :now')
            ->andWhere('t.isUsed = false')
            ->setParameter('user', $user)
            ->setParameter('type', $type)
            ->setParameter('now', new DateTimeImmutable())
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

    public function findTokenAuth(string $tokenValue,string $type = 'AUTH')
    {
        return $this->createQueryBuilder('t')
            ->andWhere('t.token = :token')
            ->andWhere('t.type = :type')
            ->setParameter('token', $tokenValue)
            ->setParameter('type', $type)
            ->getQuery()
            ->getOneOrNullResult();
    }

    public function findAuthToken(User $user , string $type = 'AUTH')
    {
        return $this->createQueryBuilder('t')
            ->andWhere('t.idUser = :user')
            ->andWhere('t.type = :type')
            ->setParameter('user', $user)
            ->setParameter('type', $type)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

//    /**
//     * @return Token[] Returns an array of Token objects
//     */
//    public function findByExampleField($value): array
//    {
//        return $this->createQueryBuilder('t')
//            ->andWhere('t.exampleField = :val')
//            ->setParameter('val', $value)
//            ->orderBy('t.id', 'ASC')
//            ->setMaxResults(10)
//            ->getQuery()
//            ->getResult()
//        ;
//    }

//    public function findOneBySomeField($value): ?Token
//    {
//        return $this->createQueryBuilder('t')
//            ->andWhere('t.exampleField = :val')
//            ->setParameter('val', $value)
//            ->getQuery()
//            ->getOneOrNullResult()
//        ;
//    }
}

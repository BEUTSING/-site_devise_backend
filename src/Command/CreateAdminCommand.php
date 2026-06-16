<?php

namespace App\Command;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

#[AsCommand(
    name: 'app:create-admin',
    description: 'Créer un compte administrateur'
)]
class CreateAdminCommand extends Command
{
    public function __construct(
        private EntityManagerInterface $em,
        private UserRepository $userRepository,
        private UserPasswordHasherInterface $passwordHasher
    ) {
        parent::__construct();
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output
    ): int {

        $email = 'admin@monsite.com';

        $existingUser = $this->userRepository->findOneBy([
            'email' => $email
        ]);

        if ($existingUser) {
            $output->writeln(
                '<error>L\'administrateur existe déjà.</error>'
            );

            return Command::FAILURE;
        }

        $user = new User();

        $user->setName('Administrateur');
        $user->setPhone('000000000');
        $user->setCity('Douala');
        $user->setEmail($email);

        $user->setRoles([
            'ROLE_ADMIN'
        ]);

        $user->setPassword(
            $this->passwordHasher->hashPassword(
                $user,
                'Admin123@'
            )
        );

        $this->em->persist($user);
        $this->em->flush();

        $output->writeln(
            '<info>Administrateur créé avec succès !</info>'
        );

        $output->writeln(
            '<comment>Email : admin@monsite.com</comment>'
        );

        $output->writeln(
            '<comment>Mot de passe : Admin123@</comment>'
        );

        return Command::SUCCESS;
    }
}
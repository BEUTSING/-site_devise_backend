<?php

namespace App\Service;

use App\Entity\User ;
use App\Enum\RoleUser;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class RegisterService
{
    private $em;
    private $passwordHasher;
    private $userrepo;
    public function __construct(EntityManagerInterface $em,
                                 UserPasswordHasherInterface $passwordHasher,UserRepository $userrepo)
    {
        $this->em=$em;
        $this->passwordHasher=$passwordHasher;
        $this->userrepo=$userrepo;
    }

    // LIST
      public function listUsers(): array
    {
    $users = $this->userrepo->findAll();

    return array_map(fn($user) => $this->formatRegister($user), $users);
    }
    // REGISTER
    public function register(Request $request): array
{
    $data = json_decode($request->getContent(), true);

    if (!$data) {
        throw new \InvalidArgumentException('Invalid JSON data');
    }

    $required = ['name','phone','city','email','password'];

    foreach ($required as $field) {
        if (empty($data[$field])) {
            throw new \InvalidArgumentException('The field '.$field.' is required');
        }
    }

    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        throw new \InvalidArgumentException('The email is not valid');
    }

    $userexists = $this->userrepo->findOneBy(['email'=>$data['email']]);
    if ($userexists) {
        throw new \RuntimeException('This user already exists');
    }

    $user = new User();
    $user->setName($data['name']);
    $user->setPhone($data['phone']);
    $user->setCity($data['city']);
    $user->setEmail($data['email']);
    $user->setPassword(
        $this->passwordHasher->hashPassword($user, $data['password'])
    );

    $this->em->persist($user);
    $this->em->flush();

    return $this->formatRegister($user);
    }

    //update user
     public function updateRegister(Request $request, int $id): array
{
    $user = $this->userrepo->find($id);

    if (!$user) {
        throw new \InvalidArgumentException('User not found');
    }

    $data = json_decode($request->getContent(), true);

    if (!$data) {
        throw new \InvalidArgumentException('Invalid JSON data');
    }

    if (isset($data['email'])) {
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new \InvalidArgumentException('The email is not valid');
        }

        $userexists = $this->userrepo->findOneBy(['email'=>$data['email']]);

        if ($userexists && $userexists->getId() !== $user->getId()) {
            throw new \RuntimeException('Email already used');
        }

        $user->setEmail($data['email']);
    }

    if (isset($data['name'])) {
        $user->setName($data['name']);
    }

    if (isset($data['phone'])) {
        $user->setPhone($data['phone']);
    }

    if (isset($data['city'])) {
        $user->setCity($data['city']);
    }

    if (isset($data['password'])) {
        $user->setPassword(
            $this->passwordHasher->hashPassword($user,$data['password'])
        );
    }

    $this->em->flush();

    return $this->formatRegister($user);
    }   
 

    //delete user

     public function deleteUsers(int $id ){

        $user=$this->userrepo->find($id);
        if(!$user){
        
             throw new \RuntimeException (
           'User not found'
        );
    }
         $this->em->remove($user);
        $this->em->flush();
        // log the delete of user

        return [
        'message' => 'User deleted successfully'
            ];     }

     private function formatRegister(User $user): array
   {
    return [
        "id" => $user->getId(),
        "name" => $user->getName(),
        "phone" => $user->getPhone(),
        "city" => $user->getCity(),
        "email" => $user->getEmail(),
        "roles" => $user->getRoles()
    ];
    }
}